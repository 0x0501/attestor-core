import assert from 'node:assert'
import { afterEach, beforeEach, describe, it, mock } from 'node:test'

import { delay } from '#src/tests/utils.ts'
import type { BGPListener } from '#src/types/index.ts'

mock.module('#src/utils/ws.ts', {
	namedExports: {
		makeWebSocket() {
			mockWs = new MockWS()
			return mockWs
		}
	}
})

describe('BGP Listener', () => {

	let listener: BGPListener
	beforeEach(async() => {
		// dynamic import to let the mock take effect
		const { createBgpListener, logger } = await import('#src/utils/index.ts')
		listener = createBgpListener(logger)
		await delay(10)

		mockWs.open()
	})

	afterEach(() => {
		listener.close()
		assert.ok(mockWs.close.mock.callCount())
	})

	it('should listen for BGP announcements', async() => {
		assert.ok(mockWs.send.mock.callCount())
	})

	it('should callback on BGP announcement overlap', async() => {
		const MOCK_CALLBACK = mock.fn()
		const cancel = listener.onOverlap(['43.240.13.21'], MOCK_CALLBACK)

		mockWs.onmessage(MOCK_MSG_EVENT)

		assert.ok(MOCK_CALLBACK.mock.callCount())

		cancel()

		mockWs.onmessage(MOCK_MSG_EVENT)

		assert.equal(MOCK_CALLBACK.mock.callCount(), 1)
	})

	it('should not callback on BGP announcement if no overlap', async() => {
		const MOCK_CALLBACK = mock.fn()
		listener.onOverlap(['44.240.13.21'], MOCK_CALLBACK)

		mockWs.onmessage(MOCK_MSG_EVENT)

		assert.ok(!MOCK_CALLBACK.mock.callCount())
	})
})

let mockWs: MockWS

const CONNECTING = 0
const OPEN = 1
const CLOSED = 3

/**
 * Models the two things about a real WebSocket that this listener gets wrong.
 *
 * It has a readyState, and send() refuses -- by throwing -- before the
 * handshake finishes, which is what undici does. And it has onerror AND
 * onclose, both of which fire for a single dropped connection.
 *
 * The mock had neither, so the reconnection path was never once exercised by a
 * test. On 2026-09-15 that path threw InvalidStateError out of an event
 * handler; Node rethrows those on nextTick, the attestor installs no
 * uncaughtException handler, and the process died with seven proofs in flight.
 */
class MockWS {
	readyState = CONNECTING
	onopen: () => void
	onerror: (err: unknown) => void
	onclose: () => void
	onmessage: (msg: MessageEvent) => void
	send = mock.fn(() => {
		if(this.readyState !== OPEN) {
			throw new Error('InvalidStateError: Sent before connected.')
		}
	})

	close = mock.fn(() => {
		this.readyState = CLOSED
	})

	/** finishes the handshake the way the real socket does, then reports it */
	open() {
		this.readyState = OPEN
		this.onopen?.()
	}
}

const MOCK_ANNOUNCEMENT_MSG = {
	'type': 'ris_message',
	'data': {
		'timestamp': 1736308898.1,
		'peer': '192.65.185.3',
		'peer_asn': '513',
		'id': '192.65.185.3-0194441339340000',
		'host': 'rrc04.ripe.net',
		'type': 'UPDATE',
		'path': [
			513,
			29222,
			29222,
			3303,
			3356,
			3223,
			55933,
			55933
		],
		'community': [
			[
				513,
				29222
			],
			[
				3223,
				2
			],
			[
				3223,
				202
			],
			[
				3223,
				666
			],
			[
				3303,
				1004
			],
			[
				3303,
				1006
			],
			[
				3303,
				3052
			],
			[
				3356,
				2
			],
			[
				3356,
				22
			],
			[
				3356,
				100
			],
			[
				3356,
				123
			],
			[
				3356,
				501
			],
			[
				3356,
				901
			],
			[
				3356,
				2065
			],
			[
				3356,
				10725
			],
			[
				22222,
				1299
			],
			[
				22233,
				10022
			],
			[
				22233,
				10030
			],
			[
				22233,
				10060
			],
			[
				29222,
				100
			],
			[
				29222,
				3303
			]
		],
		'origin': 'INCOMPLETE',
		'announcements': [
			{
				'next_hop': '192.65.185.3',
				'prefixes': [
					'43.240.13.0/24'
				]
			}
		],
		'withdrawals': []
	}
}

const MOCK_MSG_EVENT = new MessageEvent(
	'message',
	{ data: JSON.stringify(MOCK_ANNOUNCEMENT_MSG) }
)
describe('BGP Listener reconnection', () => {

	// The reconnect is deliberately delayed, so the clock is driven rather than
	// waited on: this suite should not spend a second per dropped connection.
	beforeEach(() => mock.timers.enable({ apis: ['setTimeout'] }))
	afterEach(() => mock.timers.reset())

	/**
	 * The 2026-09-15 attestor crash, as a test.
	 *
	 * ris-live drops the connection; undici fires onerror and then onclose for
	 * that one drop, and each of them reconnected. Two sockets for one failure,
	 * four when it happened twice -- production logged four
	 * "closed -> reconnecting" pairs inside eight milliseconds. The shared `ws`
	 * variable then pointed at the newest socket while an older one was still
	 * finishing its handshake, so the subscribe frame went to a socket that was
	 * CONNECTING, undici threw InvalidStateError out of the open handler, and
	 * Node rethrew it on nextTick with nobody listening.
	 *
	 * The attestor exited. Seven sessions were mid-proof: two died in the
	 * relay's prover with a nil dereference, four could not submit their claim
	 * (`write: broken pipe` to 127.0.0.1:8001) and one could not open at all.
	 * None of them was anything to do with the proofs themselves.
	 */
	it('opens one socket per dropped connection, and subscribes only on the one that connected', async() => {
		const { createBgpListener, logger } = await import('#src/utils/index.ts')
		const listener = createBgpListener(logger)
		const first = mockWs
		first.open()

		// One drop, reported twice, which is what undici does.
		first.readyState = CLOSED
		first.onerror?.(new Error('connection reset by peer'))
		first.onclose?.()

		mock.timers.tick(5_000)
		const replacement = mockWs

		assert.notStrictEqual(replacement, first, 'a dropped connection did not reconnect at all')

		// If both handlers reconnected there is a second socket behind this
		// one, and ticking again produces yet another.
		mock.timers.tick(5_000)
		assert.strictEqual(
			mockWs, replacement,
			'one dropped connection opened more than one socket; onerror and onclose both reconnected, '
			+ 'which is the race that put a subscribe frame on a socket that was still connecting'
		)

		// And the socket that finishes its handshake is the one that must get
		// the frame -- not whichever socket a shared variable happens to hold.
		assert.doesNotThrow(
			() => replacement.open(),
			'the subscribe frame went to a socket that had not connected; '
			+ 'undici throws InvalidStateError here and it kills the process'
		)

		listener.close()
	})

	it('survives an endpoint that drops every connection', async() => {
		const { createBgpListener, logger } = await import('#src/utils/index.ts')
		const listener = createBgpListener(logger)

		// Nothing here may throw, however many times it repeats: the attestor
		// installs no uncaughtException handler, so one throw out of an event
		// handler is the whole process.
		assert.doesNotThrow(() => {
			for(let i = 0; i < 8; i++) {
				const dying = mockWs
				dying.readyState = CLOSED
				dying.onerror?.(new Error('handshake failed'))
				dying.onclose?.()
				mock.timers.tick(5_000)
				assert.notStrictEqual(mockWs, dying, `round ${i} did not replace the dead socket`)
			}
		}, 'a reconnect storm threw; that is fatal to every proof in flight')

		listener.close()
	})
})
