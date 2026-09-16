import CIDR from 'ip-cidr'
import type { Logger } from 'pino'

import { BGP_WS_URL } from '#src/config/index.ts'
import type { BGPAnnouncementOverlapData, BGPListener } from '#src/types/index.ts'
import { makeWebSocket } from '#src/utils/ws.ts'

const ANNOUNCEMENT_OVERLAP = 'announcement-overlap'

/**
 * How long to wait before replacing a dropped BGP connection.
 *
 * ris-live is a third party and it goes away sometimes. Reconnecting straight
 * from the close handler turns that into as many sockets as the event loop will
 * make, which is what turned one dropped connection into four.
 */
const RECONNECT_DELAY_MS = 1000

class BGPAnnouncementOverlapEvent extends Event {

	readonly data: BGPAnnouncementOverlapData

	constructor(data: BGPAnnouncementOverlapData) {
		super(ANNOUNCEMENT_OVERLAP)
		this.data = data
	}
}

/**
 * Listens for BGP announcements and emits events whenever
 * an announcement overlaps with a target IP.
 */
export function createBgpListener(logger: Logger): BGPListener {
	let ws: ReturnType<typeof makeWebSocket>
	let closed = false
	let reconnect: ReturnType<typeof setTimeout> | undefined

	// address -> how many live sessions are watching it.
	//
	// A Set was wrong once concurrency arrived: every session to one provider
	// targets the same addresses, so the first session to finish deleted the
	// address the others were still relying on and their hijack check went
	// quiet without saying so. The count is what makes a finished session stop
	// watching only what nobody else is still watching.
	const targetIps = new Map<string, number>()
	const eventTarget = new EventTarget()

	openWs()

	return {
		onOverlap(ips, callback) {
			for(const ip of ips) {
				const held = targetIps.get(ip) ?? 0
				targetIps.set(ip, held + 1)
				if(!held) {
					send('ris_subscribe', watchFor(ip))
				}
			}

			eventTarget.addEventListener(
				ANNOUNCEMENT_OVERLAP,
				_callback
			)

			return () => {
				for(const ip of ips) {
					const held = targetIps.get(ip) ?? 0
					if(held > 1) {
						targetIps.set(ip, held - 1)
						continue
					}

					targetIps.delete(ip)
					send('ris_unsubscribe', watchFor(ip))
				}

				eventTarget.removeEventListener(
					ANNOUNCEMENT_OVERLAP,
					_callback
				)
			}

			function _callback(event: BGPAnnouncementOverlapEvent) {
				callback(event.data)
			}
		},
		close() {
			closed = true
			clearTimeout(reconnect)
			detach(ws)
			ws.close()
		}
	}

	function openWs() {
		logger.debug('connecting to BGP websocket')

		// Every handler is bound to the socket it belongs to rather than
		// reading the `ws` variable when it fires. A reconnect reassigns `ws`,
		// so a handler that reads it is not talking about the socket that
		// called it -- which is how a subscribe frame ended up on a socket that
		// was still connecting.
		const socket = makeWebSocket(BGP_WS_URL)
		ws = socket

		socket.onopen = () => onOpen(socket)
		socket.onerror = (ev) => onClose(socket, ev)
		socket.onclose = () => onClose(socket, new Error('Unexpected close'))
		socket.onmessage = ({ data }) => {
			const str = typeof data === 'string' ? data : data.toString()
			try {
				onMessage(str)
			} catch(err) {
				logger.error({ data, err }, 'error processing BGP message')
			}
		}
	}

	/**
	 * What to ask ris-live for on behalf of one watched address.
	 *
	 * The check this feeds is overlapsTargetIps, which asks whether an
	 * announced prefix CONTAINS the address. From that address's own /32 those
	 * are the less specific announcements, so that is what is subscribed to --
	 * and ris-live applies it, rather than this process reading every
	 * announcement on the internet to throw almost all of them away.
	 *
	 * It used to subscribe to `{ type: 'UPDATE' }` and nothing else, which is
	 * the unfiltered global feed. Measured on the deployed attestor: 5.1 GB
	 * received in one hour, a socket receive queue that never drained, and 70-90%
	 * of a core spent in JSON.parse on the same thread that serves every TLS
	 * tunnel and every claimTunnel. That is what forced the relay to cap itself
	 * at sixteen concurrent witnessed sessions, and past that cap requests were
	 * served unwitnessed.
	 *
	 * Verified against the live service before it was relied on: a /32 with
	 * lessSpecific returns the containing prefix, a malformed prefix comes back
	 * as `ris_error` rather than as silence, and messages that match on one
	 * prefix may carry others -- which overlapsTargetIps still filters, so the
	 * detection is the same one it always was.
	 */
	function watchFor(ip: string) {
		return { type: 'UPDATE', prefix: `${ip}/32`, lessSpecific: true }
	}

	function send(type: string, data: unknown, socket = ws): void {
		// send() on a socket that is not OPEN throws, and the callers of this
		// are event handlers: the throw does not come back to anything here, it
		// goes to the event target, which rethrows it on nextTick, which ends
		// the process. This is hijack detection. It is not worth a single
		// proof, let alone every proof in flight.
		//
		// A subscribe lost this way is picked up by the next onOpen, which
		// re-sends every address still being watched.
		try {
			socket.send(JSON.stringify({ type, data }))
		} catch(err) {
			logger.error({ err, type, data }, 'could not reach the BGP feed')
		}
	}

	function onOpen(socket: ReturnType<typeof makeWebSocket>): void {
		// Re-subscribe everything still being watched. A reconnection that did
		// not restore its subscriptions would leave the listener connected,
		// quiet and blind -- which reads exactly like a quiet internet.
		for(const ip of targetIps.keys()) {
			send('ris_subscribe', watchFor(ip), socket)
		}

		logger.info({ watching: targetIps.size }, 'connected to BGP websocket')
	}

	function onClose(socket: ReturnType<typeof makeWebSocket>, err?: Error | Event) {
		if(closed) {
			return
		}

		// One dropped connection is reported twice -- onerror and then onclose
		// -- and a socket that has already been replaced keeps reporting after
		// its successor exists. Either one reconnecting is a second socket
		// nobody asked for, and the pair of them is the storm: production
		// logged four "closed -> reconnecting" inside eight milliseconds.
		if(socket !== ws) {
			return
		}

		detach(socket)

		logger.info({ err }, 'BGP websocket closed')
		if(!err) {
			return
		}

		// Delayed, so that an endpoint refusing every connection costs one
		// socket per interval rather than as many as the event loop can make.
		logger.info('reconnecting to BGP websocket')
		reconnect = setTimeout(openWs, RECONNECT_DELAY_MS)
		reconnect.unref?.()
	}

	function detach(socket: ReturnType<typeof makeWebSocket>) {
		socket.onopen = null
		socket.onerror = null
		socket.onclose = null
		socket.onmessage = null
	}

	function onMessage(message: string): void {
		const data = JSON.parse(message)

		// ris-live refuses a subscription it cannot parse by answering, not by
		// dropping it. Swallowing that would leave the listener attached to a
		// feed carrying nothing and no way to tell that apart from an internet
		// with no announcements in it.
		if(data?.type === 'ris_error') {
			logger.error({ err: data?.data }, 'the BGP feed refused a subscription')
			return
		}

		const announcements = data?.data?.announcements

		logger.trace({ data }, 'got BGP update')

		if(!Array.isArray(announcements)) {
			return
		}

		const asPath = data?.data?.path

		for(const announcement of announcements) {
			const prefixes = announcement?.prefixes
			const nextHop = announcement?.['next_hop']

			const hasPrefixes = prefixes?.length && (nextHop || asPath)
			if(!hasPrefixes) {
				return
			}

			for(const prefix of prefixes) {
				if(!overlapsTargetIps(prefix)) {
					continue
				}

				// emit event
				eventTarget.dispatchEvent(
					new BGPAnnouncementOverlapEvent({ prefix })
				)
			}
		}
	}

	function overlapsTargetIps(prefix: string): boolean {
		// ignore all prefixes that end with /0
		if(prefix.endsWith('/0')) {
			return false
		}

		const cidr = new CIDR(prefix)
		for(const ip of targetIps.keys()) {
			if(cidr.contains(ip)) {
				return true
			}
		}

		return false
	}
}
