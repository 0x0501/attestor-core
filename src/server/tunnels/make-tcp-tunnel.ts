import type { IncomingHttpHeaders } from 'http'
import { HttpsProxyAgent } from 'https-proxy-agent'
import { Socket } from 'net'

import { CONNECTION_TIMEOUT_MS } from '#src/config/index.ts'
import type { CreateTunnelRequest } from '#src/proto/api.ts'
import { getPublicAddresses } from '#src/server/utils/generics.ts'
import { admittedWitnesses, startRosterRefresh } from '#src/server/utils/tokenswim-roster.ts'
import { planTokenswimRoute } from '#src/server/utils/tokenswim-route.ts'
import type { Logger } from '#src/types/index.ts'
import type { MakeTunnelFn, TCPSocketProperties } from '#src/types/index.ts'
import { getEnvVariable } from '#src/utils/env.ts'
import { AttestorError, logger as rootLogger } from '#src/utils/index.ts'

// FLUSH_TIMEOUT_MS bounds how long an ordinary close waits for bytes the kernel
// has already accepted to surface as 'data' events.
//
// Deliberately not the 30s that apps/relay's drainTimeout and
// apps/net/internal/witness/route's drainTimeout use. Those two wait on a peer
// that may still have something to send. This one cannot: close() has exactly
// one caller that passes no error -- the disconnectTunnel handler -- and the
// prover sends that only once its own drain has already finished. Nothing is
// left to wait *for*. The bytes this window exists to save are in the receive
// buffer already, or one RTT away from it, and Node surfaces them within a few
// turns of the event loop; half a second is several round trips of margin.
//
// The bound is also what the window costs, because every millisecond of it is
// an fd and a receive buffer held open for a session that is already over. At
// 30s and the traffic this attestor is sized for that is some hundreds of
// sockets standing around for half a minute apiece, to catch bytes that landed
// in the first millisecond.
const FLUSH_TIMEOUT_MS = 500
// An unrouted session is dialled from this host, and the resolve-then-filter
// below is what stops one from reaching loopback, a link-local metadata
// endpoint, or anything else this machine happens to be able to route to. The
// test suite has to dial loopback, so under NODE_ENV=test -- and nowhere else
// -- the host is taken as given.
//
// This replaces ALLOWED_DIRECT_HOSTS, which read the same exemption out of the
// environment as a list of host names. A guard an operator can open by adding a
// line to a .env file on a production attestor is not a guard, and the reason it
// existed -- reaching an upstream without this machine's resolver choosing the
// address -- is now what a route does properly, by handing the name to the
// Witness that dials it.
const IS_TEST = getEnvVariable('NODE_ENV') === 'test'
/**
 * ...and only to reach this machine. The suite dials its own fixtures on
 * loopback, so loopback is the whole of what the exemption owes it. Spending
 * it on every host instead would mean one stray NODE_ENV=test in a shipped
 * attestor's environment -- a CI image, a copied unit file -- turning an
 * attacker-chosen `host` into a reachable link-local metadata endpoint or an
 * address inside the private range, which is the SSRF getPublicAddresses is
 * there to refuse. Narrowed, the worst that stray buys is this host.
 */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1'])
// Tokenswim: the Witness addresses a request may name as its first hop, read
// off the chain instead of configured. A Witness's observations listener
// answers GET /v1/witnesses with the admitted roster, so an operator who
// stakes becomes dialable as soon as the chain says so; the hand-kept list
// this replaces went stale the moment a fourth Witness was admitted.
//
// Unset means Witness routing is off and every route is refused, which is the
// same fail-closed shape the empty hand-kept list had. It is loud rather than
// silent because it is not a mode anyone wants in production -- a Proof Pool
// attestor that refuses every route serves every Request unwitnessed.
const ROSTER_URL = getEnvVariable('TOKENSWIM_WITNESS_ROSTER_URL')
// Junk and empty both fall back to the default: this knob only exists to slow
// the poll down on a busy chain, and no value of it is worth failing boot over.
const ROSTER_REFRESH_MS =
	Number(getEnvVariable('TOKENSWIM_WITNESS_ROSTER_REFRESH_MS')) || 60_000
if(ROSTER_URL) {
	void startRosterRefresh(ROSTER_URL, ROSTER_REFRESH_MS, err => {
		rootLogger.warn({ err, url: ROSTER_URL }, 'failed to refresh the Witness roster; keeping the last good one')
	})
} else {
	rootLogger.warn(
		'TOKENSWIM_WITNESS_ROSTER_URL is unset; every routed session will be refused'
	)
}

type ExtraOpts = Omit<CreateTunnelRequest, 'id' | 'initialMessage'>
	& { logger: Logger }

interface ConnectResponse {
	statusCode: number
	statusText: string
	headers: IncomingHttpHeaders
}

/**
 * Builds a TCP tunnel to the given host and port.
 * If a geolocation is provided -- an HTTPS proxy is used
 * to connect to the host.
 * If a proxySessionId is provided -- a static ip is used with HTTPS proxy
 * across multiple requests with this same proxySessionId.
 *
 * HTTPS proxy essentially creates an opaque tunnel to the
 * host using the CONNECT method. Any data can be sent through
 * this tunnel to the end host.
 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/CONNECT
 *
 * The tunnel counts the bytes that cross it and keeps none of them. It used to
 * keep every message for the lifetime of the session, to be compared against
 * the claim in `claimTunnel` -- a comparison that ADR 0036 makes worthless
 * (an observer Tokenswim operates, agreeing with itself) and ADR 0040 makes
 * redundant (`assertValidClaimRequest` recomputes the ciphertext digests the
 * Witnesses signed, which is the binding strictly stronger than this one). It
 * cost a full second copy of the transcript per live session; the count is
 * what the APM label actually wanted.
 */
export const makeTcpTunnel: MakeTunnelFn<ExtraOpts, TCPSocketProperties> = async({
	onClose,
	onMessage,
	logger,
	...opts
}) => {
	let bytes = 0
	const socket = await connectTcp({ ...opts, logger })

	let closed = false
	let flushing: Promise<void> | undefined

	socket.on('data', message => {
		if(closed) {
			logger.warn('socket is closed, dropping message')
			return
		}

		onMessage?.(message)
		bytes += message.length
	})

	// Both, and not just 'close'. connectTcp leaves its own 'error' listener
	// attached after the connection is up -- the `reject` of a promise that has
	// already settled -- so a mid-session ECONNRESET had a listener (no crash)
	// whose only effect was to swallow it. 'close' then reported the session as
	// having ended cleanly, and the prover was told the upstream hung up
	// politely when it had in fact been reset.
	socket.once('error', onSocketClose)
	socket.once('close', () => onSocketClose(undefined))

	return {
		socket,
		transcriptBytes: () => bytes,
		createRequest: opts,
		async write(data) {
			bytes += data.length
			await new Promise<void>((resolve, reject) => {
				socket.write(data, err => {
					if(err) {
						reject(err)
					} else {
						resolve()
					}
				})
			})
		},
		close(err?: Error) {
			if(closed) {
				return
			}

			// An error is a real abort: whatever the kernel still holds was
			// not cleanly received, and every caller that passes one -- a
			// torn-down WS session, a BGP overlap -- has already lost the
			// client those bytes would be handed to. Drop the fd now.
			if(err) {
				socket.destroy(err)
				return
			}

			// Memoised: claimTunnel closes the tunnel again after
			// disconnectTunnel did, and a second flush would arm a second
			// window rather than join the one already running.
			flushing ||= flush()
			return flushing
		}
	}

	/**
	 * Half-closes the socket and resolves once the bytes the kernel had
	 * already accepted have surfaced as 'data' -- and so reached `onMessage`.
	 *
	 * `socket.destroy()` used to run here instead, which discarded them. Every
	 * Witness accounts for what it *forwarded* (the pipe in
	 * apps/net/internal/witness/route hashes after the write returns), so bytes
	 * sitting in this machine's receive buffer are already inside the account
	 * every seat on the route signed. Dropping them left the prover holding a
	 * transcript shorter than the one the committee agreed on, which surfaces
	 * as "all N witnesses signed the same account and it is not the one this
	 * prover holds": the tail this end threw away, reported as the seats'
	 * fault.
	 *
	 * Returning the promise is the other half of that fix. `disconnectTunnel`
	 * awaits `close()`, so the flushed bytes go out ahead of the disconnect
	 * response instead of chasing it down a socket the prover is entitled to
	 * stop reading once it has been told the tunnel is gone.
	 */
	async function flush() {
		socket.end()

		await new Promise<void>(resolve => {
			const timer = setTimeout(resolve, FLUSH_TIMEOUT_MS)
			socket.once('close', () => {
				clearTimeout(timer)
				resolve()
			})
		})

		// Nothing reads this session once close() has returned, and a peer is
		// under no obligation to hang up -- an HTTP/2 upstream keeps an idle
		// connection open for minutes, which is the case that produced the
		// original bug. Half-closing alone would leave the fd and its receive
		// buffer to the peer's discretion.
		socket.destroy()
	}

	function onSocketClose(err?: Error) {
		if(closed) {
			return
		}

		logger.debug({ err }, 'closing socket')

		closed = true

		onClose?.(err)
		onClose = undefined
	}
}

async function connectTcp(opts: ExtraOpts) {
	const { host, port, logger } = opts
	let connectTimeout: NodeJS.Timeout | undefined
	let socket: Socket | undefined
	try {
		await new Promise(async(resolve, reject) => {
			try {
				// add a timeout to ensure the connection doesn't hang
				// and cause our gateway to send out a 504
				connectTimeout = setTimeout(
					() => reject(
						new AttestorError(
							'ERROR_NETWORK_ERROR',
							'Server connection timed out'
						)
					),
					CONNECTION_TIMEOUT_MS
				)
				// The whole opts object, not a re-pack of it. Naming the
				// fields here is how `route` and `routeSlotId` were dropped
				// on the floor: the session carried a three-seat route, this
				// function forwarded four fields, and the tunnel dialled the
				// upstream direct and settled unwitnessed.
				socket = await getSocket({
					...opts,
					logger
				})
				socket.once('connect', resolve)
				socket.once('error', reject)
				socket.once('end', () => (
					reject(
						new AttestorError(
							'ERROR_NETWORK_ERROR',
							'connection closed'
						)
					)
				))
			} catch(err) {
				reject(err)
			}
		})

		logger.debug({ addr: `${host}:${port}` }, 'connected')

		return socket!
	} catch(err) {
		socket?.end()
		throw err
	} finally {
		clearTimeout(connectTimeout)
	}
}

async function getSocket(opts: ExtraOpts) {
	const { logger } = opts
	// A routed session is dialled by its last Witness, which is the egress
	// (ADR 0036). Resolving the name here and handing an address on would put
	// an IP in the CONNECT the Witness relays, so the Witness's own resolver
	// overrides never apply and the host the chain records for the session is
	// an address rather than the name the policy commits to.
	if(opts.route.length) {
		return _getSocket(opts)
	}

	const addrs = IS_TEST && LOOPBACK_HOSTS.has(opts.host.toLowerCase())
		? [opts.host]
		: await getPublicAddresses(opts.host)
	logger.debug(
		{ addrs, host: opts.host },
		'got public addresses for connection attempt'
	)
	for(const [i, addr] of addrs.entries()) {
		try {
			return await _getSocket({ ...opts, host: addr })
		} catch (err) {
			logger.error(
				{ addr, err },
				`failed to connect to address ${i + 1} of ${addrs.length}`
			)
			if(i === addrs.length - 1) {
				throw err
			}
		}
	}

	throw new AttestorError(
		'ERROR_NETWORK_ERROR',
		`Failed to connect to host ${opts.host} at any resolved address`
	)
}

async function _getSocket(
	{ host, port, route, routeSlotId, logger }: ExtraOpts,
) {
	// Read per session, not once at module load: the roster is refreshed for the
	// life of the process, and a hoisted copy would pin this attestor to whoever
	// was admitted at boot -- the exact staleness reading it off the chain fixes.
	const routePlan = planTokenswimRoute(route, routeSlotId, admittedWitnesses())
	const socket = new Socket()
	if(!routePlan) {
		socket.connect({ host, port, })
		return socket
	}

	if(!routePlan.ok) {
		throw AttestorError.badRequest(routePlan.reason, { route, routeSlotId })
	}

	const agent = new HttpsProxyAgent(
		routePlan.agentUrl,
		{ headers: routePlan.headers }
	)
	const waitForProxyRes = new Promise<ConnectResponse>(resolve => {
		// @ts-ignore
		socket.once('proxyConnect', resolve)
	})

	const proxySocket = await agent.connect(
		// ignore, because https-proxy-agent
		// expects an http request object
		// @ts-ignore
		socket,
		{
			host,
			port,
			timeout: CONNECTION_TIMEOUT_MS,
			// Opaque TCP: the caller (relay uTLS) owns the handshake. Leaving
			// this unset lets agent-base guess from the stack and wrap CONNECT
			// in a second TLS session, which the Witness then observes instead
			// of the session being proved.
			secureEndpoint: false,
		}
	)

	const res = await waitForProxyRes
	if(res.statusCode !== 200) {
		logger.error({ route, res }, 'the first hop refused the CONNECT')
		throw new AttestorError(
			'ERROR_PROXY_ERROR',
			`the first hop "${route[0]}" refused the CONNECT with status code: ${res.statusCode}, message: ${res.statusText}`,
			{
				code: res.statusCode,
				message: res.statusText,
			}
		)
	}

	// agent.connect is meant to be called from http(s).Agent, which emits
	// 'socket' so the library can resume after parsing CONNECT in paused
	// mode. Called directly, that event never fires and ServerHello sits
	// unread until the handshake times out as EOF.
	proxySocket.resume()

	process.nextTick(() => {
		// ensure connect event is emitted
		// so it can be captured by the caller
		proxySocket.emit('connect')
	})

	return proxySocket
}
