import assert from 'node:assert'
import { describe, it } from 'node:test'
import {
	MAX_ROUTE_HOPS,
	parseAdmittedWitnesses,
	planTokenswimRoute,
	ROUTE_HEADER,
	ROUTE_SLOT_HEADER,
} from '#src/server/utils/tokenswim-route.ts'

const W1 = 'w1.example.com:8443'
const W2 = 'w2.example.com:8443'
const W3 = 'w3.example.com:8443'
const ADMITTED = [W1, W2, W3]
const SLOT = '1099511632018'

// Note the default fires on an explicit `undefined` as well as on an absent
// argument, so a test about a *missing* slot id cannot go through this helper
// -- it calls planTokenswimRoute directly.
function plan(
	route: string[],
	routeSlotId: string = SLOT,
	admitted: string[] = ADMITTED
) {
	return planTokenswimRoute(route, routeSlotId, admitted)
}

function refusal(...args: Parameters<typeof plan>) {
	const result = plan(...args)
	assert.ok(result, 'expected a plan or a refusal, got "no route"')
	assert.equal(result.ok, false, `expected a refusal, got ${JSON.stringify(result)}`)
	return result.ok === false ? result.reason : ''
}

function accepted(...args: Parameters<typeof plan>) {
	const result = plan(...args)
	assert.ok(result, 'expected a plan, got "no route"')
	assert.ok(result.ok, `expected a plan, got refusal: ${result.ok === false ? result.reason : ''}`)
	return result
}

describe('tokenswim route planning', () => {
	it('leaves a request that names no route alone', () => {
		// Every pre-existing path -- direct, geoLocation, proxySessionId --
		// depends on this staying undefined rather than becoming a refusal.
		assert.equal(planTokenswimRoute(undefined, '', ADMITTED), undefined)
		assert.equal(planTokenswimRoute([], '', ADMITTED), undefined)
		assert.equal(planTokenswimRoute([], SLOT, []), undefined)
	})

	it('dials the first hop and hands the rest on', () => {
		const result = accepted([W1, W2, W3])
		assert.equal(result.agentUrl, `http://${W1}`)
		assert.equal(result.headers[ROUTE_HEADER], `${W2},${W3}`)
		assert.equal(result.headers[ROUTE_SLOT_HEADER], SLOT)
	})

	it('omits the route header when the next hop is the egress', () => {
		// Absent, not empty. An empty header is the sender saying nothing,
		// which would promote a middle hop into the position ADR 0036
		// reserves for the last one.
		const result = accepted([W1])
		assert.ok(!(ROUTE_HEADER in result.headers))
		assert.equal(result.headers[ROUTE_SLOT_HEADER], SLOT)
	})

	it('carries the slot id verbatim past the top of a double', () => {
		// The vector slot is above 2^32 on purpose and slots may go past
		// 2^53; the header spelling has to survive either way, which is why
		// the field travels as a string.
		const big = '18446744073709551615'
		assert.equal(accepted([W1], big).headers[ROUTE_SLOT_HEADER], big)
	})
})

describe('tokenswim route: the open-relay guard', () => {
	it('refuses a first hop that is not an admitted Witness', () => {
		// The whole precondition of letting a request name an address.
		for(const hop of ['127.0.0.1:22', '169.254.169.254:80', 'evil.example.com:443']) {
			const reason = refusal([hop, W2])
			assert.match(reason, /not an admitted Witness address/)
			assert.match(reason, /hop 1/)
		}
	})

	it('refuses every route when no Witness is admitted', () => {
		// Fail closed: an attestor with no list is not an open relay.
		assert.match(refusal([W1], SLOT, []), /not an admitted Witness address/)
	})

	it('does not admit a first hop by way of a later one', () => {
		assert.match(refusal(['10.0.0.1:8443', W1]), /not an admitted Witness address/)
	})

	it('reads the admitted set as a trimmed, non-empty comma list', () => {
		assert.deepEqual(parseAdmittedWitnesses(` ${W1} , ${W2} ,, `), [W1, W2])
		assert.deepEqual(parseAdmittedWitnesses(''), [])
		assert.deepEqual(parseAdmittedWitnesses(undefined), [])
	})
})

describe('tokenswim route: the slot id', () => {
	it('refuses a missing slot id rather than signing without one', () => {
		// A receipt bound to no slot is a signature two of which are not a
		// provable fault, so this refusal is the Witness's own deposit.
		for(const slot of [undefined, '']) {
			const result = planTokenswimRoute([W1, W2], slot, ADMITTED)
			assert.equal(result?.ok, false, `slot ${slot} was accepted`)
			assert.match(result?.ok === false ? result.reason : '', /which is missing/)
		}
	})

	it('refuses slot 0, the way an unset reference spells itself', () => {
		assert.match(refusal([W1], '0'), /names slot 0/)
	})

	it('refuses a second spelling of one slot', () => {
		// The leading-zero check runs before the parse, as it does in
		// chain.go, so anything starting with '0' is refused as a respelling
		// rather than as a non-number.
		for(const slot of ['0042', '0x2a']) {
			assert.match(refusal([W1], slot), /leading zeros/)
		}

		for(const slot of ['+42', ' 42', '42 ', '4_2', '4.2', '1e3', '-1']) {
			assert.match(refusal([W1], slot), /is not a route slot id/)
		}
	})

	it('refuses a slot past the top of a uint64', () => {
		assert.match(refusal([W1], '18446744073709551616'), /past the top of a uint64/)
	})
})

describe('tokenswim route: hop shape', () => {
	it('refuses a hop that is not host:port', () => {
		for(const hop of ['w1.example.com', '', ':8443', 'w1.example.com:', '2001:db8::1:8443']) {
			assert.match(
				refusal([hop], SLOT, [hop]),
				/which is not a host:port|which is empty|is not a number in 1-65535/
			)
		}
	})

	it('refuses a port whose meaning depends on the reader', () => {
		// A named port means whatever /etc/services says on the machine that
		// resolved it; a trailing path is a port a bare split reads happily.
		for(const hop of ['w1.example.com:https', 'w1.example.com:8443/connect', 'w1.example.com:08443x']) {
			assert.match(refusal([hop], SLOT, [hop]), /is not a number in 1-65535/)
		}
	})

	it('refuses port 0 and port 65536', () => {
		for(const hop of ['w1.example.com:0', 'w1.example.com:65536']) {
			assert.match(refusal([hop], SLOT, [hop]), /is not a number in 1-65535/)
		}
	})

	it('accepts a bracketed IPv6 hop', () => {
		const hop = '[2001:db8::1]:8443'
		assert.equal(accepted([hop], SLOT, [hop]).agentUrl, `http://${hop}`)
	})

	it('refuses a hop past the byte ceiling, counting bytes', () => {
		const hop = `${'a'.repeat(251)}:8443` // 256 bytes
		assert.match(refusal([hop], SLOT, [hop]), /256 bytes, the ceiling is 255/)
	})

	it('refuses a route longer than any chain will anchor', () => {
		const route = Array.from({ length: MAX_ROUTE_HOPS + 1 }, (_, i) => `w${i}.example.com:8443`)
		assert.match(refusal(route, SLOT, route), /17 hops, the ceiling is 16/)
	})

	it('refuses a route that names one Witness twice', () => {
		assert.match(refusal([W1, W2, W1]), /hop 3 of the route repeats/)
	})
})
