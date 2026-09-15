import { afterEach, beforeEach, describe, it } from 'node:test'

import assert from 'assert'
import type { TLSSocket } from 'tls'

import { AttestorClient } from '#src/client/index.ts'
import { makeRpcTcpTunnel } from '#src/client/tunnels/make-rpc-tcp-tunnel.ts'
import { makeRpcTlsTunnel } from '#src/client/tunnels/make-rpc-tls-tunnel.ts'
import { describeWithServer } from '#src/tests/describe-with-server.ts'
import { delay } from '#src/tests/utils.ts'
import type { AttestorError } from '#src/utils/index.ts'
import { logger } from '#src/utils/index.ts'

describeWithServer('RPC Tunnel', opts => {

	const { mockHttpsServer, getClientOnServer } = opts

	let client: AttestorClient
	beforeEach(async() => {
		client = opts.client
	})

	afterEach(async() => {
		await client.terminateConnection()
	})

	it('should connect to a server via RPC tunnel', async() => {
		// setup tunnel for listening & then
		// connect to it via RPC
		const tunnel = await makeRpcTcpTunnel({ tunnelId: 1, client })
		await client.rpc(
			'createTunnel',
			{
				id: 1,
				host: 'localhost',
				port: opts.mockhttpsServerPort,
			}
		)

		const ws = getClientOnServer()
		const socketTunnel = ws?.tunnels[1]
		assert.ok(socketTunnel)

		await tunnel.close()

		// check that the server actually closed the tunnel
		// upon our request.
		//
		// Which code comes back is the *peer's* call, not ours. Node swaps in
		// `writeAfterFIN` -- the one that stamps EPIPE -- only once this socket
		// has seen the peer's FIN, so a peer that closes back gives EPIPE while
		// one that holds the connection half-open (the idle HTTP/2 upstream
		// this close() exists for) gives ERR_STREAM_WRITE_AFTER_END. Measured
		// 100/100 and 40/40 respectively: a state transition, not a race.
		//
		// What belongs to close() is the distinction asserted here. An ordinary
		// close now *ends* the socket before dropping it, so neither code can
		// be ERR_STREAM_DESTROYED -- that one is reserved for close(err), which
		// drops the fd without ending it, and telling the two apart is the
		// whole point of the split. Pinning the exact half-close code instead
		// would be asserting how the mock server hangs up.
		await assert.rejects(
			async() => socketTunnel?.write(Buffer.from('hello')),
			(err: AttestorError) => {
				// Widened: AttestorError types `code` as the proto error enum,
				// and these are Node's own socket codes travelling through it.
				const code: string = err.code
				assert.ok(
					code === 'EPIPE' || code === 'ERR_STREAM_WRITE_AFTER_END',
					`an ordinary close must end the socket, not destroy it; got ${code}`
				)
				return true
			}
		)
	})

	describe('TLS', () => {
		it('should do a TLS handshake via RPC tunnel', async() => {
			const ws = getClientOnServer()
			const tunnel = await makeRpcTlsTunnel({
				request: {
					id: 1,
					host: 'localhost',
					port: opts.mockhttpsServerPort,
				},
				tlsOpts: {
					verifyServerCertificate: false,
				},
				logger: client.logger,
				connect(initMessages) {
					client.sendMessage(...initMessages)
						.catch(() => {})
					// ensure that the client hello message
					// was sent to the server along the
					// "createTunnel" request -- that saves
					// us a round-trip
					assert.ok(initMessages[1].tunnelMessage)
					return client
				},
			})

			assert.ok(ws?.tunnels[1])

			await tunnel.close()
		})

		it('should setup a 0-RTT TLS connection', async() => {
			let client2: AttestorClient | undefined
			const tunnel = await makeRpcTlsTunnel({
				request: {
					id: 1,
					host: 'localhost',
					port: opts.mockhttpsServerPort,
				},
				tlsOpts: {
					verifyServerCertificate: false,
				},
				logger: client.logger,
				connect(initMessages) {
					client2 = new AttestorClient({
						url: opts.serverUrl,
						logger: logger.child({ client: 2 }),
						initMessages
					})
					return client2
				},
			})

			await tunnel.close()
			await client2?.terminateConnection()
		})

		it('should gracefully handle a TLS disconnection alert', async() => {
			let socket: TLSSocket | undefined
			mockHttpsServer.server.once('secureConnection', s => {
				socket = s
			})

			let closeResolve: ((value?: Error) => void) | undefined
			await makeRpcTlsTunnel({
				request: {
					id: 1,
					host: 'localhost',
					port: opts.mockhttpsServerPort,
				},
				tlsOpts: {
					verifyServerCertificate: false,
				},
				logger: client.logger,
				connect(initMessages) {
					client.sendMessage(...initMessages)
						.catch(() => {})
					return client
				},
				onClose(err) {
					closeResolve?.(err)
				},
			})

			await delay(100)

			assert.ok(socket)
			socket?.end()

			const err = await new Promise<Error | undefined>((resolve) => {
				closeResolve = resolve
			})
			// since it was a graceful close, there should be no error
			assert.ok(!err)
		})

		it('should handle TLS handshake errors', async() => {
			await assert.rejects(
				async() => makeRpcTlsTunnel({
					request: {
						id: 1,
						host: 'localhost',
						port: opts.mockhttpsServerPort,
					},
					tlsOpts: {
						applicationLayerProtocols: [
							'invalid-protocol'
						]
					},
					logger: client.logger,
					connect(initMessages) {
						client.sendMessage(...initMessages)
							.catch(() => {})
						return client
					},
				}),
				(err: AttestorError) => {
					assert.match(err.message, /NO_APPLICATION_PROTOCOL/)
					return true
				}
			)
		})

		// The two halves of the tunnel-creation error test asserted on the
		// geoLocation and proxySessionId validators, which existed to keep a
		// malformed value out of the HTTPS_PROXY_URL template. Neither the
		// template nor the values select an exit any more -- the route does --
		// and a route that does not check out is refused by planTokenswimRoute,
		// which tokenswim-route.test.ts covers hop by hop.
	})
})