/**
 * Tokenswim: turns the Witness route a request names into the first hop to
 * dial and the CONNECT headers to hand on.
 *
 * This lives apart from make-tcp-tunnel.ts on purpose. Everything here is a
 * pure function over strings with no import outside this file, so it can be
 * exercised by `node --test` without the socket, the proxy agent or the
 * protobuf runtime that make-tcp-tunnel.ts drags in. The rule the fork most
 * needs held -- that a request cannot point this attestor at an arbitrary
 * address -- is the rule that would otherwise have no test at all.
 *
 * The header names, the widths and the spellings mirror
 * apps/net/internal/witness/route/chain.go, which is the end that reads them.
 * Where the two could differ, this end is the stricter one: a route refused
 * here fails at the caller with a reason, where the same route refused at hop
 * one fails as an opaque proxy error on a machine the caller cannot see.
 */

/**
 * RouteHeader carries the hops the session has still to cross, in order,
 * comma-separated. It is absent at the egress, which is how the last Witness
 * learns it is the egress (ADR 0036).
 */
export const ROUTE_HEADER = 'X-Tokenswim-Route'

/**
 * RouteSlotHeader carries the chain-allocated route slot. Present at every
 * hop including the last: a Witness that signs a receipt with no slot in its
 * preimage can double-sign without leaving evidence, so the slot is what
 * makes two conflicting signatures a self-contained fault.
 */
export const ROUTE_SLOT_HEADER = 'X-Tokenswim-Route-Slot-Id'

/**
 * MAX_ROUTE_HOPS matches route.MaxRouteHops, which in turn tracks
 * x/provider/types.MinWitnessesCeiling. A longer list is a route no chain
 * will ever anchor.
 */
export const MAX_ROUTE_HOPS = 16

/** Longest single hop, matching route.maxHopBytes: 253 for a DNS name, 5 for a port. */
const MAX_HOP_BYTES = 255

export type RoutePlan =
	| {
		readonly ok: true
		/** Proxy URL for the first hop. Plain CONNECT -- a Witness is not a TLS proxy. */
		readonly agentUrl: string
		/** Handed to HttpsProxyAgent, which writes them into the CONNECT. */
		readonly headers: Record<string, string>
	}
	| { readonly ok: false, readonly reason: string }

/**
 * Reads the set of Witness addresses this attestor may dial as a first hop.
 *
 * The list is a snapshot of the chain's admitted Witness endpoints, held as
 * process config because that is the shape of the thing: it changes when the
 * chain admits or retires a Witness, not per session. The chain stays the
 * authority; this is the operator's copy of its answer.
 */
export function parseAdmittedWitnesses(raw: string | undefined): string[] {
	return raw?.split(',').map(v => v.trim()).filter(v => v !== '') ?? []
}

/**
 * Builds the plan for a request-borne route, or refuses it with a reason.
 *
 * Returns undefined when the request names no route at all, which leaves
 * every pre-existing path -- direct, geoLocation, proxySessionId -- untouched.
 */
export function planTokenswimRoute(
	route: readonly string[] | undefined,
	routeSlotId: string | undefined,
	admittedWitnesses: readonly string[],
): RoutePlan | undefined {
	if(!route?.length) {
		return undefined
	}

	if(route.length > MAX_ROUTE_HOPS) {
		return refuse(`the route names ${route.length} hops, the ceiling is ${MAX_ROUTE_HOPS}`)
	}

	const seen = new Set<string>()
	for(const [i, hop] of route.entries()) {
		const bad = hopProblem(hop)
		if(bad) {
			return refuse(`hop ${i + 1} of the route is ${JSON.stringify(hop)}, ${bad}`)
		}

		// A frozen route holds distinct operators, so a route naming one hop
		// twice is a route no chain assigned. Relaying it would produce two
		// receipts from one Witness against a set that froze it once.
		if(seen.has(hop)) {
			return refuse(`hop ${i + 1} of the route repeats ${JSON.stringify(hop)}`)
		}

		seen.add(hop)
	}

	// The open-relay guard, and the reason a request may name an address at
	// all. Without it the attestor is a CONNECT relay for whoever asks: the
	// destination has always been caller-chosen, but the machine in between
	// was not, and an unconstrained first hop reaches loopback, link-local
	// metadata and anything else this host can route to.
	//
	// Only the first hop is checked, because the first hop is the only
	// address this process dials. The hops behind it are dialled by Witnesses,
	// each of which has to make this same refusal for itself.
	if(!admittedWitnesses.includes(route[0])) {
		return refuse(
			`hop 1 of the route is ${JSON.stringify(route[0])}, which is not an admitted Witness address`
		)
	}

	const slot = slotProblem(routeSlotId)
	if(slot) {
		return refuse(`the ${ROUTE_SLOT_HEADER} value is ${JSON.stringify(routeSlotId ?? '')}, ${slot}`)
	}

	const headers: Record<string, string> = {
		// Unconditional, where the route header is not: every hop signs a
		// receipt and every receipt is bound to the slot.
		[ROUTE_SLOT_HEADER]: routeSlotId!
	}
	// Absent rather than empty at the last hop. An empty header would read as
	// "the sender set this field and said nothing", which is a different claim
	// from "there is nothing left", and only the second one means egress.
	if(route.length > 1) {
		headers[ROUTE_HEADER] = route.slice(1).join(',')
	}

	return { ok: true, agentUrl: `http://${route[0]}`, headers }
}

function refuse(reason: string): RoutePlan {
	return { ok: false, reason }
}

/**
 * Names what is wrong with one hop, or returns undefined.
 *
 * Stricter than a bare host/port split, on purpose. A split alone reads
 * "w1.example:8443/connect" as port "8443/connect" and is happy, and it
 * accepts named ports like "https", whose meaning is whatever /etc/services
 * says on the machine that resolved it. A field the chain compares byte for
 * byte cannot have a validity that depends on its reader.
 */
function hopProblem(hop: string): string | undefined {
	if(hop === '') {
		return 'which is empty'
	}

	// Bytes, not UTF-16 units: the ceiling is the one chain.go applies.
	const bytes = new TextEncoder().encode(hop).length
	if(bytes > MAX_HOP_BYTES) {
		return `which is ${bytes} bytes, the ceiling is ${MAX_HOP_BYTES}`
	}

	const split = splitHostPort(hop)
	if(!split || split.host === '') {
		return 'which is not a host:port'
	}

	if(!/^[0-9]+$/.test(split.port)) {
		return `whose port ${JSON.stringify(split.port)} is not a number in 1-65535`
	}

	const port = Number(split.port)
	if(port < 1 || port > 65535) {
		return `whose port ${JSON.stringify(split.port)} is not a number in 1-65535`
	}

	return undefined
}

/** Mirrors Go's net.SplitHostPort for the shapes a route hop can take. */
function splitHostPort(value: string) {
	if(value.startsWith('[')) {
		const end = value.indexOf(']')
		if(end < 0 || value[end + 1] !== ':') {
			return undefined
		}

		return { host: value.slice(1, end), port: value.slice(end + 2) }
	}

	const colon = value.indexOf(':')
	// Too many colons is a bare IPv6 address, which has to be bracketed
	// before a port can be told from the address.
	if(colon < 0 || value.indexOf(':', colon + 1) >= 0) {
		return undefined
	}

	return { host: value.slice(0, colon), port: value.slice(colon + 1) }
}

/**
 * Names what is wrong with the slot id, or returns undefined.
 *
 * Absent is refused rather than read as slot zero. A Witness that will sign a
 * receipt bound to no slot can double-sign as much as it likes and never
 * leave evidence, so the one caller that may omit the header is the one
 * relaying for a producer that wants the escape hatch.
 *
 * Strict about spelling, because a uint64 has one decimal spelling and this
 * end only takes that one: no sign, no whitespace, no leading zeros, no 0x.
 * Two spellings of one number are two strings a log or a comparison could
 * tell apart, and leniency buys nothing when every sender is a program.
 */
function slotProblem(raw: string | undefined): string | undefined {
	if(!raw) {
		return 'which is missing; every hop of a route signs a receipt bound to its slot'
	}

	if(raw.length > 1 && raw[0] === '0') {
		return 'which is a route slot id with leading zeros'
	}

	if(!/^[0-9]+$/.test(raw)) {
		return 'which is not a route slot id'
	}

	const slot = BigInt(raw)
	if(slot === 0n) {
		return 'which names slot 0, the way an unset reference spells itself'
	}

	if(slot > 0xffffffffffffffffn) {
		return 'which is past the top of a uint64'
	}

	return undefined
}
