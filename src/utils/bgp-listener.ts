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

	const targetIps = new Set<string>()
	const eventTarget = new EventTarget()

	openWs()

	return {
		onOverlap(ips, callback) {
			for(const ip of ips) {
				targetIps.add(ip)
			}

			eventTarget.addEventListener(
				ANNOUNCEMENT_OVERLAP,
				_callback
			)

			return () => {
				for(const ip of ips) {
					targetIps.delete(ip)
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

	function onOpen(socket: ReturnType<typeof makeWebSocket>): void {
		const subscriptionMessage = {
			type: 'ris_subscribe',
			data: {
				type: 'UPDATE',
			},
		}

		// send() on a socket that is not OPEN throws, and this is an event
		// handler: the throw does not return to anyone here, it goes to the
		// event target, which rethrows it on nextTick, which ends the process.
		// This is hijack detection. It is not worth a single proof, let alone
		// every proof in flight.
		try {
			socket.send(JSON.stringify(subscriptionMessage))
		} catch(err) {
			logger.error({ err }, 'could not subscribe to BGP updates')
			return
		}

		logger.info('connected to BGP websocket')
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
		for(const ip of targetIps) {
			if(cidr.contains(ip)) {
				return true
			}
		}

		return false
	}
}
