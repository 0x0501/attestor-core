import assert from 'node:assert'
import { describe, it } from 'node:test'
import {
	admittedWitnesses,
	parseRoster,
	startRosterRefresh,
} from '#src/server/utils/tokenswim-roster.ts'

const W1 = '100.96.0.7:9120'
const W2 = '100.96.0.8:9120'

const ROSTER = {
	height: 45113,
	witnesses: [
		{ operator: 'tsm1a', routeEndpoint: W1, observationsEndpoint: '100.96.0.7:9121' },
		{ operator: 'tsm1b', routeEndpoint: W2, observationsEndpoint: '100.96.0.8:9121' },
	],
}

const ROSTER_URL = 'http://roster.test/v1/witnesses'
// Long enough that the poll cannot fire a second time inside a test and
// overwrite what the test just asserted.
const NO_SECOND_POLL_MS = 600_000

let warnings: unknown[] = []

// The module holds process state on purpose -- it is one roster per attestor --
// so these run in declaration order and share it. Swapping the global fetch
// rather than opening a socket is the whole reason this module imports nothing:
// the guard is testable without a network.
function refresh(answer: () => unknown) {
	warnings = []
	globalThis.fetch = (async() => {
		const value = answer()
		return value instanceof Response ? value : Response.json(value)
	}) as typeof fetch
	return startRosterRefresh(ROSTER_URL, NO_SECOND_POLL_MS, err => warnings.push(err))
}

describe('tokenswim roster: parsing', () => {
	it('reads the route endpoints out of a well-formed body', () => {
		assert.deepEqual(parseRoster(ROSTER), [W1, W2])
	})

	it('drops entries with no usable routeEndpoint, keeping the rest', () => {
		// One bad record on chain must not cost the whole roster: the alternative
		// is an empty list, and an empty list refuses every route.
		const body = {
			witnesses: [
				{ routeEndpoint: ` ${W1} ` },
				{ routeEndpoint: '' },
				{ routeEndpoint: 42 },
				{ operator: 'tsm1c' },
				null,
				'not an object',
				{ routeEndpoint: W2 },
			],
		}
		assert.deepEqual(parseRoster(body), [W1, W2])
	})

	it('reads nothing out of a body that is not a roster', () => {
		for(const body of [
			null, undefined, 42, 'witnesses', [], {},
			{ witnesses: null }, { witnesses: 'w1:9120' }, { height: 1 },
		]) {
			assert.deepEqual(parseRoster(body), [], `for ${JSON.stringify(body)}`)
		}
	})
})

describe('tokenswim roster: refresh', () => {
	it('admits nothing before the first successful fetch', () => {
		// Fail closed. planTokenswimRoute turns this empty list into a refusal, so
		// an attestor that has never reached a Witness dials nobody.
		assert.deepEqual(admittedWitnesses(), [])
	})

	it('serves the roster once it lands', async() => {
		await refresh(() => ROSTER)
		assert.deepEqual(admittedWitnesses(), [W1, W2])
		assert.deepEqual(warnings, [])
	})

	it('keeps the last good roster when the fetch fails', async() => {
		await refresh(() => {
			throw new Error('connection refused')
		})
		assert.deepEqual(admittedWitnesses(), [W1, W2])
		assert.equal(warnings.length, 1)
	})

	it('keeps the last good roster when the answer is not 200', async() => {
		// A chain node answering 503 is a blip, not an eviction. Reading a 503
		// body as a roster would empty the list and take the Proof Pool down.
		await refresh(() => new Response('upstream is starting', { status: 503 }))
		assert.deepEqual(admittedWitnesses(), [W1, W2])
		assert.equal(warnings.length, 1)
	})

	it('keeps the last good roster when the body is not JSON', async() => {
		await refresh(() => new Response('<html>gateway</html>', { status: 200 }))
		assert.deepEqual(admittedWitnesses(), [W1, W2])
		assert.equal(warnings.length, 1)
	})
})
