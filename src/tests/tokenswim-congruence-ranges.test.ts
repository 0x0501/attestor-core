import assert from 'node:assert'
import { describe, it } from 'node:test'

import { REDACTION_CHAR_CODE } from '@reclaimprotocol/zk-symmetric-crypto'

import type { Window } from '#src/providers/tokenswim-window/index.ts'
import { assertCongruent } from '#src/providers/tokenswim-window/index.ts'

/**
 * `assertCongruent` used to paint two `Uint8Array(data.length)` bitmaps, one for
 * the challenged bytes and one for the covered ones -- two more full-length
 * copies of a transcript that can reach the 160 MiB response ceiling, to answer
 * a question about a handful of intervals. It now merges each set into sorted
 * disjoint ranges and walks them with a cursor.
 *
 * Interval containment is exactly the kind of rewrite that is subtly wrong at
 * the edges, so the bitmap version is kept here verbatim as an oracle and the
 * two are asserted to agree -- on the same `data`, the same windows and the
 * same proven ranges -- across the named edge cases and a randomised sweep.
 *
 * Agreement means: same verdict, and when both throw, the same message. The
 * message names a byte index, so an off-by-one that still threw would be caught
 * by the comparison rather than passed over.
 */

/** The implementation being replaced, verbatim. */
function bitmapCongruent(
	direction: string,
	data: Uint8Array,
	windows: Window[],
	proven: Window[]
) {
	const challenged = new Uint8Array(data.length)
	for(const w of windows) {
		challenged.fill(1, w.fromIndex, w.toIndex)
	}

	const covered = new Uint8Array(data.length)
	for(const p of proven) {
		covered.fill(1, p.fromIndex, p.toIndex)
	}

	let ambiguous = 0
	for(let i = 0; i < data.length; i++) {
		const looksRedacted = data[i] === REDACTION_CHAR_CODE
		if(challenged[i] && looksRedacted) {
			if(!covered[i]) {
				throw new Error(
					`${direction} byte ${i} was challenged and the claim proves nothing`
					+ ' over it'
				)
			}

			ambiguous++
			continue
		}

		if(!challenged[i] && !looksRedacted) {
			throw new Error(`${direction} byte ${i} was revealed but never challenged`)
		}
	}

	return ambiguous
}

type Outcome = { ok: true; ambiguous: number } | { ok: false; message: string }

function run(
	fn: typeof bitmapCongruent,
	data: Uint8Array,
	windows: Window[],
	proven: Window[]
): Outcome {
	try {
		return { ok: true, ambiguous: fn('client', data, windows, proven) }
	} catch(err) {
		return { ok: false, message: (err as Error).message }
	}
}

function assertAgrees(
	what: string,
	data: Uint8Array,
	windows: Window[],
	proven: Window[]
) {
	const oracle = run(bitmapCongruent, data, windows, proven)
	const actual = run(assertCongruent, data, windows, proven)
	assert.deepStrictEqual(
		actual,
		oracle,
		`${what}: range walk and bitmap disagree`
		+ `\n  windows ${JSON.stringify(windows)}`
		+ `\n  proven  ${JSON.stringify(proven)}`
		+ `\n  data    ${JSON.stringify(Array.from(data))}`
	)
}

const R = REDACTION_CHAR_CODE
/** A byte that is neither the sentinel nor anything special. */
const V = 65

/** `revealed` marks the byte positions to leave as payload; the rest redacted. */
function bytes(length: number, revealed: number[]) {
	const out = new Uint8Array(length).fill(R)
	for(const i of revealed) {
		out[i] = V
	}

	return out
}

function makeRng(seed: number) {
	let s = seed >>> 0
	return () => {
		s = (s * 1664525 + 1013904223) >>> 0
		return s / 0x100000000
	}
}

describe('tokenswim congruence: range walk equals bitmap', () => {
	it('agrees on the named edge cases', () => {
		const w = (from: number, to: number): Window => (
			{ fromIndex: from, toIndex: to }
		)

		const cases: [string, Uint8Array, Window[], Window[]][] = [
			// Nothing challenged and nothing revealed: the vacuous pass.
			['empty ranges, all redacted', bytes(8, []), [], []],
			// Nothing challenged but a byte revealed: leakage, must throw.
			['empty ranges, a revealed byte', bytes(8, [3]), [], []],
			['zero-length data', new Uint8Array(0), [w(0, 0)], [w(0, 0)]],
			['single byte challenged, covered and revealed', bytes(1, [0]), [w(0, 1)], [w(0, 1)]],
			['single byte challenged, covered, redacted', bytes(1, []), [w(0, 1)], [w(0, 1)]],
			// The cheap forgery: answer a challenge with nothing at all.
			['single byte challenged, uncovered, redacted', bytes(1, []), [w(0, 1)], []],
			// An empty range must contribute nothing; `mergeRanges` drops it and
			// `fill` was a no-op on it, so the two only agree if both do.
			['degenerate empty window', bytes(6, [2]), [w(2, 3), w(4, 4)], [w(2, 3)]],
			['inverted window is dropped', bytes(6, [2]), [w(2, 3), w(5, 1)], [w(2, 3)]],
			// Adjacent ranges must fuse into one, not leave a seam at the join.
			['adjacent ranges', bytes(10, [0, 1, 2, 3, 4, 5]), [w(0, 3), w(3, 6)], [w(0, 3), w(3, 6)]],
			['adjacent ranges, gap byte revealed', bytes(10, [0, 1, 2, 3, 4, 5, 6]), [w(0, 3), w(3, 6)], [w(0, 6)]],
			['overlapping ranges', bytes(10, [1, 2, 3, 4, 5]), [w(1, 4), w(3, 6)], [w(1, 6)]],
			['nested ranges', bytes(10, [1, 2, 3, 4, 5, 6, 7]), [w(1, 8), w(3, 5)], [w(1, 8)]],
			['range touching 0', bytes(10, [0, 1, 2]), [w(0, 3)], [w(0, 3)]],
			['range touching length', bytes(10, [7, 8, 9]), [w(7, 10)], [w(7, 10)]],
			['range spanning the whole buffer', bytes(10, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]), [w(0, 10)], [w(0, 10)]],
			// `fill` clamps a too-large end index; the merge has to as well.
			['range past length', bytes(10, [8, 9]), [w(8, 40)], [w(8, 40)]],
			['range starting past length', bytes(10, []), [w(20, 40)], [w(20, 40)]],
			// Sorting is the merge's job, not the caller's.
			['out-of-order input', bytes(12, [8, 9, 2, 3]), [w(8, 10), w(2, 4)], [w(8, 10), w(2, 4)]],
			['out-of-order and overlapping', bytes(12, [6, 7, 8, 2, 3]), [w(6, 9), w(2, 4), w(7, 9)], [w(2, 4), w(6, 9)]],
			// A challenged range with no cover: every redacted byte in it throws
			// at the first index, so the message pins which index that is.
			['challenged range with no cover', bytes(10, []), [w(3, 7)], []],
			['challenged range covered only in part', bytes(10, []), [w(3, 7)], [w(3, 5)]],
			['challenged range, cover starts late', bytes(10, []), [w(3, 7)], [w(4, 7)]],
			// One proven range spanning two challenge windows, and the reverse.
			['cover spans two challenged ranges', bytes(16, []), [w(2, 5), w(9, 12)], [w(0, 16)]],
			['two covers under one challenged range', bytes(16, []), [w(2, 12)], [w(2, 7), w(7, 12)]],
			['covers with a hole under one challenge', bytes(16, []), [w(2, 12)], [w(2, 6), w(8, 12)]],
			// Mixed reveal inside a window is the ordinary case.
			['mixed reveal inside a window', bytes(16, [4, 6, 8]), [w(3, 12)], [w(3, 12)]],
			['reveal exactly at a window edge', bytes(16, [3, 11]), [w(3, 12)], [w(3, 12)]],
			['reveal one past a window edge', bytes(16, [12]), [w(3, 12)], [w(3, 12)]],
			['reveal one before a window edge', bytes(16, [2]), [w(3, 12)], [w(3, 12)]],
			// Cover with no challenge is not an error by itself.
			['cover outside every challenge', bytes(16, []), [w(2, 5)], [w(0, 16)]],
			['many small alternating ranges', bytes(40, [0, 2, 4, 6, 8]),
				Array.from({ length: 10 }, (_, i) => w(i * 2, i * 2 + 1)),
				Array.from({ length: 10 }, (_, i) => w(i * 2, i * 2 + 1))],
		]

		for(const [what, data, windows, proven] of cases) {
			assertAgrees(what, data, windows, proven)
		}
	})

	it('agrees on randomised cases', () => {
		const rng = makeRng(0xbadc0de)
		for(let t = 0; t < 3000; t++) {
			const length = Math.floor(rng() * 48)
			const data = new Uint8Array(length)
			for(let i = 0; i < length; i++) {
				// Biased towards the sentinel: a mostly-revealed buffer throws on
				// byte 0 nearly every time and exercises nothing past it.
				data[i] = rng() < 0.75 ? R : V
			}

			const pick = () => {
				const n = Math.floor(rng() * 4)
				return Array.from({ length: n }, () => {
					const from = Math.floor(rng() * (length + 4))
					const to = from + Math.floor(rng() * 12)
					return { fromIndex: from, toIndex: to }
				})
			}

			assertAgrees(`random case ${t}`, data, pick(), pick())
		}
	})

	it('agrees when the proven set is a subset of the challenged set', () => {
		// The interesting shape for the "challenged and proves nothing" branch:
		// coverage that lags the challenge by one byte at each end.
		const rng = makeRng(0x1234)
		for(let t = 0; t < 800; t++) {
			const length = 8 + Math.floor(rng() * 40)
			const data = new Uint8Array(length).fill(R)
			const windows: Window[] = []
			const proven: Window[] = []
			let at = 0
			while(at < length) {
				const width = 1 + Math.floor(rng() * 8)
				const to = Math.min(length, at + width)
				windows.push({ fromIndex: at, toIndex: to })
				if(rng() < 0.7) {
					proven.push({
						fromIndex: at + (rng() < 0.3 ? 1 : 0),
						toIndex: to - (rng() < 0.3 ? 1 : 0),
					})
				}

				at = to + Math.floor(rng() * 3)
			}

			assertAgrees(`subset case ${t}`, data, windows, proven)
		}
	})
})

/**
 * The one place the two implementations are meant to differ, asserted rather
 * than left to be discovered.
 *
 * `Uint8Array.prototype.fill` reads a negative index as an offset from the end,
 * so `fill(1, -2, 16)` painted bytes 14 and 15 rather than nothing. A range list
 * has no such convention, and clipping a negative up to 0 would *widen* the
 * range -- which for `covered` means a challenged byte counted as proven. So a
 * range with a negative endpoint is dropped, which can only refuse more.
 *
 * Unreachable in practice for `clientProven` / `serverProven` (`readRanges`
 * refuses a negative before this runs) and for the derived windows; `modelChunk`
 * is the one unvalidated path, and it is prover-chosen regardless.
 */
describe('tokenswim congruence: negative offsets fail closed', () => {
	const ALL_REDACTED = new Uint8Array(16).fill(R)

	it('drops a negative challenge range instead of wrapping it to the tail', () => {
		// Byte 15 is revealed; nothing non-negative challenges it.
		const data = bytes(16, [15])
		const windows: Window[] = [{ fromIndex: -2, toIndex: 16 }]
		const proven: Window[] = [{ fromIndex: 14, toIndex: 16 }]

		// Oracle: `fill(1, -2, 16)` paints 14 and 15, so the reveal at 15 passes.
		assert.deepStrictEqual(
			run(bitmapCongruent, data, windows, proven),
			{ ok: true, ambiguous: 1 }
		)

		// New: the window is dropped, so byte 15 is revealed and unchallenged.
		assert.deepStrictEqual(run(assertCongruent, data, windows, proven), {
			ok: false,
			message: 'client byte 15 was revealed but never challenged',
		})
	})

	it('drops a negative cover range instead of crediting the tail', () => {
		const windows: Window[] = [{ fromIndex: 14, toIndex: 16 }]
		const proven: Window[] = [{ fromIndex: -2, toIndex: 16 }]

		// Oracle: `fill(1, -2, 16)` credits 14 and 15 with cover they never had.
		assert.deepStrictEqual(
			run(bitmapCongruent, ALL_REDACTED, windows, proven),
			{ ok: true, ambiguous: 2 }
		)

		// New: the cover is dropped, so the challenge is answered by nothing.
		assert.deepStrictEqual(run(assertCongruent, ALL_REDACTED, windows, proven), {
			ok: false,
			message: 'client byte 14 was challenged and the claim proves nothing over it',
		})
	})
})
