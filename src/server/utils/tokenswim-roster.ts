/**
 * Tokenswim: the attestor's copy of the chain's admitted-Witness roster, read
 * from a Witness rather than configured by hand.
 *
 * This lives apart from make-tcp-tunnel.ts for the reason tokenswim-route.ts
 * does: everything here is a function over a parsed body and a URL, with no
 * import outside the file, so it can be exercised by `node --test` without a
 * socket, a proxy agent or the protobuf runtime that make-tcp-tunnel.ts drags
 * in. It decides which addresses this process will dial as a first hop, which
 * is the open-relay guard, and a guard with no test is one nobody notices
 * breaking.
 *
 * It replaces a hand-maintained list. x/witness admits on stake, so a list
 * copied by hand is stale the moment a fourth operator stakes: eligible on
 * chain, already frozen into route slots, and refused by every attestor until
 * somebody edits a file and restarts. Reading WitnessRecord.route_endpoint
 * back off the chain closes that window without an operator in it.
 */

/**
 * How long a single refresh may take before it is abandoned.
 *
 * Without it a connection that opens and then hangs stalls the poll loop for
 * good: the roster freezes at whatever it last held and nothing is logged,
 * because from the loop's side the request has simply not finished yet.
 */
const FETCH_TIMEOUT_MS = 10_000

/**
 * How long to wait before the first retry, doubling up to the poll interval.
 *
 * Only bootstrapping backs off. Until a roster lands every route is refused,
 * so an attestor that booted a moment before its Witness is dead weight, and
 * a flat one-minute interval would spend that minute refusing sessions it
 * could already have served.
 */
const BOOTSTRAP_RETRY_MS = 500

let admitted: string[] = []
let bootstrapped = false

/**
 * The addresses this attestor will dial as a first hop, as of the last
 * successful refresh.
 *
 * Empty before the first one lands, and deliberately so: planTokenswimRoute
 * turns an empty list into a refusal, so an attestor that has never reached a
 * Witness fails closed rather than dialling whatever a request names.
 */
export function admittedWitnesses(): string[] {
	return admitted
}

/**
 * Pulls the route endpoints out of a `GET /v1/witnesses` body.
 *
 * Defensive rather than schema-strict, because this body crosses a process
 * boundary this code is not compiled against: one malformed entry must not
 * cost the whole roster, or a single bad record on chain takes the Proof Pool
 * down. Anything that is not a non-empty routeEndpoint string is dropped, and
 * whatever survives is still checked hop by hop by planTokenswimRoute -- this
 * function decides what is on the list, not what a well-formed address is.
 */
export function parseRoster(body: unknown): string[] {
	if(typeof body !== 'object' || body === null) {
		return []
	}

	const { witnesses } = body as { witnesses?: unknown }
	if(!Array.isArray(witnesses)) {
		return []
	}

	const endpoints: string[] = []
	for(const witness of witnesses) {
		if(typeof witness !== 'object' || witness === null) {
			continue
		}

		const endpoint = (witness as { routeEndpoint?: unknown }).routeEndpoint
		if(typeof endpoint === 'string' && endpoint.trim() !== '') {
			endpoints.push(endpoint.trim())
		}
	}

	return endpoints
}

/**
 * Polls `url` for the roster for the life of the process. Resolves once the
 * first attempt has been made, so a caller that wants to wait for bootstrap
 * can; the loop keeps running either way.
 *
 * A failed fetch or an unusable body keeps the last good roster and logs a
 * warning. The roster changes when an operator stakes or unstakes, not per
 * session, so serving one a few minutes stale is strictly better than
 * refusing every route -- a chain node blipping must not take the whole Proof
 * Pool down with it.
 */
export function startRosterRefresh(
	url: string,
	intervalMs: number,
	onWarn: (err: unknown) => void,
): Promise<void> {
	let delay = BOOTSTRAP_RETRY_MS

	const tick = async() => {
		try {
			const res = await fetch(url, {
				signal: AbortSignal.timeout(FETCH_TIMEOUT_MS)
			})
			if(!res.ok) {
				throw new Error(`the roster URL answered HTTP ${res.status}`)
			}

			admitted = parseRoster(await res.json())
			bootstrapped = true
			delay = intervalMs
		} catch(err) {
			onWarn(err)
			delay = bootstrapped ? intervalMs : Math.min(delay * 2, intervalMs)
		}

		// unref: the poller is background work. A pending timer must not be the
		// reason the process refuses to exit.
		setTimeout(tick, delay).unref()
	}

	return tick()
}
