import assert from 'node:assert'
import { fork } from 'node:child_process'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { after, describe, it } from 'node:test'
import { fileURLToPath } from 'node:url'

import { logger, strToUint8Array } from '#src/utils/index.ts'

/**
 * Tokenswim: what an ordinary close owes the Witnesses that signed for the
 * session.
 *
 * Every Witness on a route accounts for what it *forwarded* -- the pipe in
 * `apps/net/internal/witness/route` hashes a chunk after the write returns --
 * so a byte the kernel here has accepted is already inside the account every
 * seat signed, read or not. `close()` used to call `socket.destroy()`, which
 * discards exactly those bytes: the prover's transcript came up short of an
 * account the whole committee agreed on, and the session was refused as "all N
 * witnesses signed the same account and it is not the one this prover holds".
 * Four of seven production refusals had that shape, every one of them a Codex
 * SSE response that ended early.
 *
 * The window is small and it is not a timeout. `DisconnectTunnel` arrives on
 * the WS while the upstream's last bytes are sitting in this machine's receive
 * buffer, both fds come back ready in one turn of the event loop, and whichever
 * the poller serves first decides whether those bytes are read or thrown away.
 *
 * So the Witness and its upstream run in a process of their own and the test
 * stops this one's event loop outright. Blocking the loop *is* the condition,
 * not an imitation of it: bytes land in the kernel, Node cannot emit them, and
 * `close()` runs before it ever gets the chance. In one process the Witness
 * would stop forwarding at the same instant and leave nothing buffered to lose.
 */

/** A slot id of the shape `x/session` allocates, as in tokenswim-route.test.ts. */
const SLOT = '1099511632018'
/** Long enough for the Witness to forward its whole response into this process. */
const BLOCK_MS = 300
/** Long enough that the roster's poll cannot fire a second time in this file. */
const NO_SECOND_POLL_MS = 600_000
/**
 * Generous against FLUSH_TIMEOUT_MS (500ms) and unmistakable against the 30s
 * this window was first written with. The upstream in the fixture never hangs
 * up, so an unbounded wait would hang here rather than fail.
 */
const CLOSE_CEILING_MS = 5_000

type Ready = {
	type: 'ready'
	upstreamPort: number
	witnessPort: number
	payloadBytes: number
}

type Report = { type: 'report', forwarded: number, connectHead: string }

const fixture = fork(
	fileURLToPath(new URL('./tokenswim-witness-fixture.ts', import.meta.url)),
	// Bare: the fixture must not inherit the test runner's loader flags and
	// start running tests of its own.
	{ execArgv: [] }
)

const nextMessage = <T>() => new Promise<T>(resolve => (
	fixture.once('message', message => resolve(message as T))
))

const ready = await nextMessage<Ready>()
const WITNESS = `127.0.0.1:${ready.witnessPort}`

// The admitted-Witness roster, served where a Witness's observations listener
// serves it. Reaching the route through this rather than a seeded list is the
// point: an address the attestor will dial has to have come off the chain.
const roster = createServer((_, res) => {
	res.setHeader('content-type', 'application/json')
	res.end(JSON.stringify({
		height: 1,
		witnesses: [{ operator: 'tsm1fixture', routeEndpoint: WITNESS }],
	}))
})
await new Promise<void>(resolve => roster.listen(0, '127.0.0.1', resolve))

// Read once, at module load, so both have to be set before the import below.
process.env.TOKENSWIM_WITNESS_ROSTER_URL =
	`http://127.0.0.1:${(roster.address() as AddressInfo).port}/v1/witnesses`
process.env.TOKENSWIM_WITNESS_ROSTER_REFRESH_MS = `${NO_SECOND_POLL_MS}`

const { makeTcpTunnel } = await import('#src/server/tunnels/make-tcp-tunnel.ts')
const { admittedWitnesses } = await import('#src/server/utils/tokenswim-roster.ts')

// The first poll is kicked off at import and the promise is kept inside, so
// there is nothing to await but the result of it.
for(let tries = 0; !admittedWitnesses().includes(WITNESS); tries++) {
	assert.ok(tries < 200, 'the Witness roster never bootstrapped')
	await new Promise(resolve => setTimeout(resolve, 25))
}

describe('TCP tunnel', () => {

	after(() => {
		fixture.kill()
		roster.close()
	})

	it('hands over every byte the Witness forwarded, including the ones that arrived while the loop was blocked', async() => {
		let received = 0
		const tunnel = await makeTcpTunnel({
			host: '127.0.0.1',
			port: ready.upstreamPort,
			route: [WITNESS],
			routeSlotId: SLOT,
			logger,
			onMessage(data) {
				received += data.length
			},
		})

		await tunnel.write(strToUint8Array('GET / HTTP/1.1\r\nHost: upstream\r\n\r\n'))

		// No await between these two lines: nothing may run the loop, or the
		// socket drains itself and there is no window left to test.
		blockEventLoop(BLOCK_MS)
		const closedAt = Date.now()
		await tunnel.close()
		const closeMs = Date.now() - closedAt

		fixture.send('report')
		const report = await nextMessage<Report>()

		assert.equal(
			received,
			report.forwarded,
			'the attestor delivered fewer bytes than the Witness accounted for'
		)
		assert.equal(
			report.forwarded,
			ready.payloadBytes,
			'the Witness should have forwarded the whole response'
		)
		assert.ok(
			closeMs < CLOSE_CEILING_MS,
			`close() took ${closeMs}ms; it waits for the bytes it already has, not for a peer`
		)
		assert.match(
			report.connectHead,
			new RegExp(`^CONNECT 127\\.0\\.0\\.1:${ready.upstreamPort} `),
			'the upstream must be dialled by the Witness, by name, not direct'
		)
		assert.match(
			report.connectHead,
			new RegExp(`x-tokenswim-route-slot-id: ${SLOT}`, 'i'),
			'every hop signs a receipt bound to the slot, so the slot must cross'
		)
	})

	it('reports a torn-down session as an error rather than a clean close', async() => {
		// The 'error' listener used to be commented out, leaving connectTcp's
		// settled `reject` as the only one: an error had a listener, so nothing
		// crashed and nothing was reported either, and the session was handed
		// on as having ended politely.
		let closed: ((err?: Error) => void) | undefined
		const onClosed = new Promise<Error | undefined>(resolve => {
			closed = resolve
		})

		const tunnel = await makeTcpTunnel({
			host: '127.0.0.1',
			port: ready.upstreamPort,
			route: [WITNESS],
			routeSlotId: SLOT,
			logger,
			onClose(err) {
				closed?.(err)
			},
		})

		const reset = new Error('WS session terminated')
		await tunnel.close(reset)

		assert.equal(await onClosed, reset)
	})
})

/**
 * Spins rather than awaiting, on purpose. Any await here would hand the loop
 * back and let the socket drain, which is precisely the state this test needs
 * not to be in.
 */
function blockEventLoop(ms: number) {
	const until = Date.now() + ms
	while(Date.now() < until) {
		// hold the loop shut
	}
}
