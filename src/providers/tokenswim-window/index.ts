import { concatenateUint8Arrays } from '@reclaimprotocol/tls'
import { REDACTION_CHAR_CODE } from '@reclaimprotocol/zk-symmetric-crypto'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { areUint8ArraysEqual } from '@reclaimprotocol/tls'
import { TranscriptMessageSenderType } from '#src/proto/api.ts'
import { getBytes } from 'ethers'

import type { Provider } from '#src/types/index.ts'
import { uint8ArrayToStr } from '#src/utils/generics.ts'

/**
 * Relay Proof provider: both directions are redacted everywhere except a set of
 * challenge windows whose offsets the prover does not choose. The attestor
 * recomputes the offsets from the Witnesses' signatures and the ciphertext
 * digests they committed to, so a window that the prover moved is a window the
 * attestor rejects.
 */

export type Window = { fromIndex: number; toIndex: number }

/** One ASCII byte, the way the offset formula spells a direction. */
export type Direction = 'c' | 's'

/** One Witness's commitment: the key it signs as, and what it signed. */
export type Attestation = {
	publicKey: string | undefined
	signature: string | undefined
}

export const WINDOW_BYTES = 128

/**
 * The floor on how many Witnesses seed one proof. One Witness that the relay
 * operator also runs is no Witness at all. Nothing here enforces a ceiling:
 * every Witness added past the floor puts another signature into the seed, and
 * the chain is meant to grow — but the chain is also where the ceiling
 * actually lives: `MaxWitnessReceipts` in
 * `packages/proof-protocol/validate/validate.go` and `MinWitnessesCeiling` in
 * `apps/net/x/provider/types/params.go` both cap it at 16. A claim built past
 * that many attestations is this same bug at the other end: accepted here,
 * relayed, answered 200, and refused at anchoring. Left unmirrored on
 * purpose — a ceiling here is a separate decision, not bundled into this fix.
 *
 * Must equal `MinWitnesses` in `packages/relay-proof-go/challenge/challenge.go`,
 * `MinWitnessesFloor` in `apps/net/x/provider/types/params.go`, and
 * `MinWitnessReceipts` in `packages/proof-protocol/validate/validate.go` — a
 * value one validator accepts and another rejects is a proof nobody can both
 * build and anchor.
 */
export const MIN_WITNESSES = 3

/**
 * BLS12-381 in the IETF basic scheme — public key in G1, signature in G2 — which
 * is what the Go Witness in `packages/relay-proof-go/blssig` signs with.
 *
 * The scheme is not interchangeable with the ECDSA used for the claim owner next
 * door, and the difference is the whole reason this file exists in this shape:
 * BLS is *unique*. One key and one message admit exactly one valid signature, so
 * a Witness cannot resign the same commitment until the draw suits the party
 * being proven. Under ECDSA the signer picks the nonce, and one colluding
 * Witness out of any number could steer every window on its own — it signs last,
 * against everyone else's fixed contribution.
 */
const BLS = bls12_381.longSignatures

/**
 * Every Witness signs one commitment covering both directions at once:
 *
 *     SHA-256("TOKENSWIM_WITNESS_RECEIPT_V3\0" ‖ routeSlot ‖ transcriptRoot
 *             ‖ clientDigest ‖ serverDigest ‖ clientLen ‖ serverLen ‖ leafCount)
 *
 * over the raw 32-byte digests, client first — not their hex spellings. Signing
 * each direction separately would double the signature count and prove nothing
 * more, since both digests are published beside the signatures.
 *
 * The challenge seed is the digest of the ciphertext, and this attestor is one
 * of the parties that saw it. The others are the Witnesses in the network path,
 * which signed the same digests before anything was disclosed — so a prover that
 * names a digest suiting its windows has to corrupt every one of them. Without
 * this the seed would be a claim parameter the prover chooses, and the offsets
 * would be worth nothing.
 *
 * Returns the signatures as bytes, in ascending order of the key that made them,
 * because they are also the seed the windows are drawn from: verifying them and
 * seeding from them is one step and cannot be got out of order.
 */
/**
 * Tie the digests the Witnesses signed to the bytes this claim actually carries.
 *
 * Without this the seed is a value the prover names. The Witnesses really did
 * sign the digests in `params` — but of some session, not necessarily this one.
 * A prover holding attestations from earlier sessions can therefore submit
 * today's transcript while citing whichever past signature set draws the
 * windows it would rather be judged on, and every other check still passes: the
 * signatures verify, the offsets derive from them honestly, and the reveals are
 * congruent with the offsets. Measured, not supposed — the replay is accepted
 * by every check the provider makes on its own.
 *
 * `message` is the raw ciphertext record as it crossed the wire, unchanged by
 * the reveal machinery, and the prover's own digest is `SHA-256` over exactly
 * those bytes in exactly this order. So this recomputation is the same value a
 * Witness arrived at from the stream that crossed it — which is what makes the
 * binding come from a party that is not the prover (ADR 0036).
 */
/**
 * The name this provider is registered under. Exported so `providers/index.ts`
 * registers with it and the claim-path check gates on it: one string, so a
 * rename cannot leave the check quietly matching nothing.
 */
export const PROVIDER_NAME = 'tokenswimWindow'

/**
 * The claim path's entry point, called for every provider and doing nothing for
 * any but this one.
 *
 * It lives here rather than in `assertValidClaimRequest` so that the parameter
 * shape, the hex decoding and the provider name stay in the file that owns
 * them; upstream gains one line and no knowledge of what we put in `params`.
 */
export async function assertSeedBindsTheTranscript(
	provider: string,
	parameters: string,
	transcript: { sender: unknown; message: Uint8Array }[]
) {
	if(provider !== PROVIDER_NAME) {
		return
	}

	let params: { clientDigest?: string; serverDigest?: string }
	try {
		params = JSON.parse(parameters || '{}')
	} catch {
		throw new Error('the claim parameters are not JSON')
	}
	if(!params.clientDigest || !params.serverDigest) {
		throw new Error(
			'the claim names no ciphertext digests, so there is nothing binding its'
			+ ' witnesses to the bytes it carries'
		)
	}

	await assertDigestsBindTheTranscript(
		transcript,
		hexToBytes(params.clientDigest),
		hexToBytes(params.serverDigest)
	)
}

/**
 * A TLS 1.3 record costs 5 header bytes and a 16-byte AEAD tag around the
 * encrypted body, and the last byte of that body is the real content type
 * rather than application data. So a record carries `length - 22` bytes of the
 * direction's application data, which is the same arithmetic
 * `decryptTranscript` does with `AUTH_TAG_BYTE_LENGTH` and
 * `extractApplicationDataFromTranscript` finishes with its `- 1`.
 *
 * A TLS 1.2 session lands elsewhere by both counts — an explicit nonce it does
 * not subtract, a content-type byte it does not have — and comes out with a
 * different total, which the length comparison below refuses. That is the
 * intended answer: this provider is a TLS 1.3 design (ADR 0035) and a 1.2
 * session should be told so rather than measured wrong.
 */
const RECORD_OVERHEAD = 5 + 16 + 1
const APPLICATION_DATA = 23
/**
 * The outer record type of every encrypted TLS 1.3 record, the encrypted
 * handshake included — 23 again, because that is the disguise TLS 1.3 puts on
 * everything after the ServerHello. A record that is not one of these is the
 * plaintext handshake, which `decryptTranscript` never sees: it starts at
 * `processHandshake`'s `nextMsgIndex`, and a ClientHello counted here would
 * push every offset after it out of the receipt's coordinates.
 */
const ENCRYPTED_RECORD = 23

/**
 * Tie the ranges the claim says it proved to the proofs the claim carries.
 *
 * The sibling check above binds the *seed*; this one binds what answering the
 * challenge is worth. Redaction is marked with `'*'`, which is also a legal
 * payload byte, so the provider reading the decrypted receipt cannot tell a
 * revealed `'*'` from a byte that was withheld (ADR 0035). Its congruence check
 * therefore counted that case and continued — which is a challenge a prover can
 * answer with nothing at all: reveal none of a window, and every remaining
 * check still passes.
 *
 * The proofs already say where they land, and the provider is the one thing in
 * the claim path that cannot see them: `assertValidProviderReceipt` is handed
 * the decrypted application data and the parameters, and nothing else. So the
 * prover declares the ranges it proved, this recomputes them from the proofs
 * the transcript carries, and refuses a claim naming any other; the provider
 * then refuses a challenged byte no declared range covers.
 *
 * **The coordinate system is the direction's application data**, the one the
 * challenge windows are already in, the one `RevealedChunk.Offset` publishes
 * and the one `apps/verifier`'s own coverage rule reads. A proof's `startIdx`
 * is record-relative, so the translation has to happen on one side or the
 * other, and doing it here rather than in the provider is what keeps a fourth
 * coordinate system out of the protocol.
 *
 * Translating needs the record bases, and a record only contributes one if it
 * reaches `extractApplicationDataFromTranscript`. That function decides on the
 * content type, which is inside the ciphertext — so for a directly revealed
 * record this code cannot decide it at all. Hence the length: the prover names
 * each direction's total, this arrives at it from the transcript counting only
 * records it can classify, and the provider arrives at it from the receipt.
 * Records this skips are a subset of the records the receipt keeps, so the two
 * totals agree only when the two sets are identical — which is the whole of
 * what makes the offsets mean the same thing at both ends.
 */
export function assertProvenRangesBindTheTranscript(
	provider: string,
	parameters: string,
	transcript: TranscriptForCoverage
) {
	if(provider !== PROVIDER_NAME) {
		return
	}

	let params: {
		clientLength?: unknown
		serverLength?: unknown
		clientProven?: unknown
		serverProven?: unknown
	}
	try {
		params = JSON.parse(parameters || '{}')
	} catch {
		throw new Error('the claim parameters are not JSON')
	}

	for(const [side, lengthKey, provenKey] of [
		['client', 'clientLength', 'clientProven'],
		['server', 'serverLength', 'serverProven'],
	] as const) {
		const named = params[lengthKey]
		if(typeof named !== 'number' || !Number.isInteger(named) || named < 0) {
			throw new Error(
				`the claim names no ${side} application-data length, so its proven`
				+ ' ranges are offsets into nothing'
			)
		}

		const { length, ranges } = provenApplicationRanges(transcript, side)
		if(length !== named) {
			throw new Error(
				`the claim says the ${side} direction carried ${named} bytes of`
				+ ` application data and its transcript carries ${length}: the offsets`
				+ ' it proved and the offsets it is challenged at are then in different'
				+ ' coordinates'
			)
		}

		const declared = readRanges(params[provenKey], `${side}Proven`)
		if(spell(declared) !== spell(ranges)) {
			throw new Error(
				`the claim says its ${side} proofs cover ${spell(declared) || '(nothing)'}`
				+ ` and the proofs it carries cover ${spell(ranges) || '(nothing)'}`
			)
		}
	}
}

type TranscriptForCoverage = {
	sender: unknown
	message: Uint8Array
	reveal?: {
		directReveal?: { key?: Uint8Array } | undefined
		zkReveal?: {
			proofs?: { startIdx?: number; redactedPlaintext?: Uint8Array }[]
		} | undefined
	} | undefined
}[]

/**
 * One direction's application-data length and the ranges of it some ZK proof
 * covers, both read from the undecrypted transcript.
 *
 * The three cases are `decryptTranscript`'s own, in its order: a direct reveal
 * wins, then a ZK one, and a record claiming neither is redacted whole.
 */
function provenApplicationRanges(
	transcript: TranscriptForCoverage,
	side: 'client' | 'server'
) {
	const ranges: Window[] = []
	let base = 0

	for(const message of transcript.filter(m => isFrom(m, side))) {
		// The plaintext handshake — ClientHello, ServerHello, the change-cipher
		// dummy — carries no reveal because there is nothing to reveal, and it
		// is behind `nextMsgIndex` by the time anything is decrypted.
		if(message.message[0] !== ENCRYPTED_RECORD) {
			continue
		}

		// The encrypted handshake is revealed this way and is not application
		// data; so are the session tickets, which ride the same keys after it.
		// Whether a third kind exists cannot be decided here, and does not have
		// to be: a directly revealed record that *is* application data is one
		// the receipt counts and this does not, and the two totals then
		// disagree.
		if(message.reveal?.directReveal?.key?.length) {
			continue
		}

		const appLength = message.message.length - RECORD_OVERHEAD
		if(appLength < 0) {
			throw new Error(
				`a ${side} record is ${message.message.length} bytes, which is shorter`
				+ ' than a TLS 1.3 record can be'
			)
		}

		const proofs = message.reveal?.zkReveal?.proofs
		if(proofs?.length) {
			// TLS 1.3 hides the real content type in the last plaintext byte, and
			// a record whose last byte is not application data is dropped from the
			// receipt — silently, which is one of the four protocol facts ADR 0035
			// writes down. Skipping it here is what keeps the bases aligned; a
			// prover that hides that byte loses the record rather than shifting
			// every offset after it.
			if(byteFromProofs(proofs, appLength) !== APPLICATION_DATA) {
				continue
			}

			for(const { startIdx = 0, redactedPlaintext } of proofs) {
				// A chunk that begins at or past the content-type byte proves no
				// application data at all, and every maximum-sized record produces
				// one because the chunk size divides 16384.
				if(startIdx >= appLength) {
					continue
				}

				ranges.push({
					fromIndex: base + startIdx,
					toIndex: base + Math.min(
						startIdx + (redactedPlaintext?.length ?? 0), appLength
					),
				})
			}
		}

		base += appLength
	}

	return { length: base, ranges: mergeRanges(ranges) }
}

/** The reconstructed plaintext byte at `index`, or -1 if no proof covers it. */
function byteFromProofs(
	proofs: { startIdx?: number; redactedPlaintext?: Uint8Array }[],
	index: number
) {
	for(const { startIdx = 0, redactedPlaintext } of proofs) {
		const at = index - startIdx
		if(redactedPlaintext && at >= 0 && at < redactedPlaintext.length) {
			return redactedPlaintext[at]
		}
	}

	return -1
}

/**
 * The canonical spelling of a covered set: sorted, and touching ranges fused.
 * Both ends have to arrive at the same list from the same bytes, and "the
 * chunks, in the order they were proved" is a spelling that changes when the
 * chunking does. What is being compared is which bytes are covered.
 */
function mergeRanges(ranges: Window[]) {
	const out: Window[] = []
	for(const r of [...ranges].sort((a, b) => a.fromIndex - b.fromIndex)) {
		if(r.toIndex <= r.fromIndex) {
			continue
		}

		const last = out[out.length - 1]
		if(last && r.fromIndex <= last.toIndex) {
			last.toIndex = Math.max(last.toIndex, r.toIndex)
		} else {
			out.push({ ...r })
		}
	}

	return out
}

/**
 * Read a `[[from, to], …]` parameter. AJV has not run at the claim path's first
 * check, so the shape is asserted here rather than assumed — the same reason
 * the digest check parses its own JSON.
 */
function readRanges(value: unknown, name: string) {
	if(!Array.isArray(value)) {
		throw new Error(`the claim's ${name} is not a list of ranges`)
	}

	return value.map(pair => {
		if(
			!Array.isArray(pair) || pair.length !== 2
			|| !pair.every(n => typeof n === 'number' && Number.isInteger(n) && n >= 0)
		) {
			throw new Error(`the claim's ${name} holds something that is not a range`)
		}

		return { fromIndex: pair[0] as number, toIndex: pair[1] as number }
	})
}

/**
 * A transcript reaches this file in either of two shapes — the numeric proto
 * enum on the wire, or the string form the decrypted receipt uses — and the
 * codebase already deals with both. Sniffing one and missing the other would
 * filter every message out and check nothing at all, which fails closed on the
 * digest but *open* on the coverage below, so it is written once rather than
 * twice.
 */
const isFrom = (m: { sender: unknown }, side: 'client' | 'server') => (
	m.sender === side
	|| m.sender === (side === 'client'
		? TranscriptMessageSenderType.TRANSCRIPT_MESSAGE_SENDER_TYPE_CLIENT
		: TranscriptMessageSenderType.TRANSCRIPT_MESSAGE_SENDER_TYPE_SERVER)
)

/**
 * Fed record by record rather than over one joined buffer. `crypto.subtle` has
 * no streaming API, so binding the digest used to mean allocating a copy of the
 * whole direction — at the 160 MiB response ceiling, the single largest live
 * allocation on the claim path, for a value that is a fold over the same bytes
 * either way. SHA-256 is defined on the byte stream, not on how it is handed
 * over, so the digest is identical to the byte; `tokenswim-digest-streaming.test.ts`
 * holds both implementations side by side and asserts exactly that.
 *
 * `@noble/hashes` rather than `node:crypto`: this file is bundled into
 * `attestor-browser.min.mjs` by way of `providers/index.ts`, and esbuild builds
 * it with `platform: 'browser'`, where a `node:crypto` import does not resolve.
 * Noble is already here — `@noble/curves` below is built on it.
 */
export async function assertDigestsBindTheTranscript(
	transcript: { sender: unknown; message: Uint8Array }[],
	clientDigest: Uint8Array,
	serverDigest: Uint8Array
) {
	for(const [side, named] of [
		['client', clientDigest],
		['server', serverDigest],
	] as const) {
		const hash = sha256.create()
		let seen = 0
		for(const message of transcript) {
			if(!isFrom(message, side)) {
				continue
			}

			hash.update(message.message)
			seen++
		}

		if(!seen) {
			throw new Error(
				`no ${side} messages in the transcript to bind the digest to`
			)
		}

		const actual = hash.digest()
		if(!areUint8ArraysEqual(actual, named)) {
			throw new Error(
				`the claim names a ${side} digest the Witnesses signed, but not one of`
				+ ' the bytes it carries: the seed would be a value the prover chose'
			)
		}
	}
}

/**
 * The domain tag and the field order of observation.Commitment in
 * packages/relay-proof-go. A Witness signs seven fields, not two, and hashing
 * the wrong preimage is indistinguishable from a bad signature -- which is how
 * this read for a release: every witnessed session was refused with "did not
 * sign the ciphertext this claim is about" while the chain, which computes the
 * same commitment, accepted the identical receipts at anchor.
 */
const RECEIPT_DOMAIN_V3 = new TextEncoder().encode('TOKENSWIM_WITNESS_RECEIPT_V3\0')

export type ReceiptFields = {
	routeSlotId: number
	transcriptRoot: Uint8Array
	clientDigest: Uint8Array
	serverDigest: Uint8Array
	clientApplicationLen: number
	serverApplicationLen: number
	responseLeafCount: number
}

/**
 * Builds the 153-byte preimage. The raw 32-byte digests go in, never their hex
 * spellings: a signer that hashed the bytes and a verifier that hashed the
 * spelling disagree on every session, and the disagreement looks like a forged
 * signature rather than like a bug.
 */
export function receiptPreimageV3(f: ReceiptFields): Uint8Array {
	for(const [name, digest] of [
		['transcript_root', f.transcriptRoot],
		['client_digest', f.clientDigest],
		['server_digest', f.serverDigest],
	] as const) {
		if(digest.length !== 32) {
			throw new Error(`${name} is ${digest.length} bytes, a digest is 32`)
		}
	}

	const be64 = (n: number) => {
		const out = new Uint8Array(8)
		new DataView(out.buffer).setBigUint64(0, BigInt(n))
		return out
	}

	const be32 = (n: number) => {
		const out = new Uint8Array(4)
		new DataView(out.buffer).setUint32(0, n)
		return out
	}

	const parts = [
		RECEIPT_DOMAIN_V3,
		be64(f.routeSlotId),
		f.transcriptRoot,
		f.clientDigest,
		f.serverDigest,
		be64(f.clientApplicationLen),
		be64(f.serverApplicationLen),
		be32(f.responseLeafCount),
	]
	const joined = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
	let at = 0
	for(const p of parts) {
		joined.set(p, at)
		at += p.length
	}

	return joined
}

export async function assertWitnessesSawTheSameBytes(
	fields: ReceiptFields,
	attestations: Attestation[] | undefined
) {
	const witnesses = attestations ?? []
	if(witnesses.length < MIN_WITNESSES) {
		throw new Error(
			`the claim carries ${witnesses.length} witness attestation(s) of the ciphertext,`
			+ ` and ${MIN_WITNESSES} is the floor: one witness the relay operator also runs`
			+ ' is no witness at all'
		)
	}

	const commitment = new Uint8Array(
		await globalThis.crypto.subtle.digest('SHA-256', receiptPreimageV3(fields))
	)
	const message = BLS.hash(commitment)

	const seen = new Set<string>()
	const verified: { publicKey: Uint8Array; signature: Uint8Array }[] = []
	for(const [index, witness] of witnesses.entries()) {
		if(!witness?.publicKey || !witness?.signature) {
			throw new Error(`witness ${index} carries no public key or no signature`)
		}

		const publicKey = hexToBytes(witness.publicKey)
		const signature = hexToBytes(witness.signature)

		// A malformed point makes noble throw rather than return false, and the
		// two are the same answer here: this is not a signature by that key.
		let ok = false
		try {
			ok = BLS.verify(signature, message, publicKey)
		} catch(err) {
			throw new Error(`witness ${witness.publicKey} is not a usable attestation: ${err}`)
		}

		if(!ok) {
			throw new Error(
				`witness ${witness.publicKey} did not sign the ciphertext this claim is about`
			)
		}

		// Distinct identities, not merely distinct entries: n witnesses sharing a
		// key are one witness with extra steps, and they would contribute one
		// signature's worth of unpredictability while looking like n.
		const identity = witness.publicKey.toLowerCase()
		if(seen.has(identity)) {
			throw new Error(
				`${identity} attested twice; witnesses sharing a key are one witness with extra steps`
			)
		}

		seen.add(identity)
		verified.push({ publicKey, signature })
	}

	// Sorted by identity, not left in the order the claim listed them: n
	// signatures admit n! orderings, and an ordering the prover chooses is n!
	// free draws at the challenge it is supposed to be unable to steer.
	verified.sort((a, b) => compareBytes(a.publicKey, b.publicKey))

	return verified.map(w => w.signature)
}

/**
 * from_i = be32(SHA-256(sig_1 ‖ … ‖ sig_n ‖ digest ‖ direction ‖ be32(i))[0:4]) mod span
 *
 * where the signatures are in ascending order of the key that made them,
 * span = max(length - min(WINDOW_BYTES, length), 1), and a draw that overlaps a
 * window already held is discarded rather than kept.
 *
 * The seed is every Witness's signature, which exists only once the session has
 * closed and that Witness has committed to the ciphertext it relayed: a seed the
 * prover could choose is a seed the prover could grind. The direction byte is in
 * there because both directions are drawn from the same signatures, and without
 * it a request and a response of the same length would be challenged at
 * identical offsets — one grinding attempt would have bought both.
 *
 * The Go prover derives the same windows in `relay-proof-go/challenge`. Any
 * change here is a protocol change and has to move on both sides at once; the
 * fixed point both sides are checked against is
 * `packages/relay-proof-go/challenge/testdata/window-vectors.json`.
 */
export async function deriveWindows(
	signatures: Uint8Array[],
	digest: Uint8Array,
	direction: Direction,
	length: number,
	count: number
) {
	if(length <= 0 || count <= 0 || !signatures.length) {
		return []
	}

	const size = Math.min(WINDOW_BYTES, length)
	const span = Math.max(length - size, 1)
	const windows: Window[] = []

	// The counter is the only part of the seed that moves between draws, so the
	// rest is laid out once and only the trailing four bytes are rewritten.
	const seed = concatenateUint8Arrays([
		...signatures, digest, Uint8Array.of(direction.charCodeAt(0)),
	])
	const input = new Uint8Array(seed.length + 4)
	input.set(seed)
	const counter = new DataView(input.buffer, seed.length, 4)

	for(let i = 0; windows.length < count && i < count * 64; i++) {
		counter.setUint32(0, i)

		const draw = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', input))
		const from = new DataView(draw.buffer, draw.byteOffset, 4).getUint32(0) % span
		const candidate = { fromIndex: from, toIndex: Math.min(length, from + size) }

		// Two overlapping windows cost two windows' proofs for less than two
		// windows' coverage, so a colliding draw is discarded and redrawn.
		if(windows.some(w => candidate.fromIndex < w.toIndex && w.fromIndex < candidate.toIndex)) {
			continue
		}

		windows.push(candidate)
	}

	return windows.sort((a, b) => a.fromIndex - b.fromIndex)
}

/**
 * Sorted and fused, which is what `mergeRanges` already does, plus one thing
 * the bitmap did implicitly and a range list does not.
 *
 * `Uint8Array.prototype.fill` reads a negative index as an offset from the
 * *end*, so `fill(1, -2, 16)` on a 16-byte buffer painted bytes 14 and 15
 * rather than nothing. A range list has no such convention, and there is no
 * reading of a negative offset that is both faithful and safe: clipping it up
 * to 0 *widens* the range, and a wider `covered` set is a challenged byte
 * treated as proven when it is not. So a range with a negative endpoint is
 * dropped. Dropping is fail-closed for both sets — a narrower `covered` can
 * only refuse more, and a narrower `challenged` can only refuse more.
 *
 * Every input the callers can actually produce is non-negative and unaffected:
 * `clientProven` / `serverProven` have been through `readRanges`, which refuses
 * a negative, and `deriveWindows` returns offsets it computed. `modelChunk` is
 * the one value that reaches here straight off the claim with only a bare
 * `{ type: 'number' }` schema behind it — and it is prover-chosen either way,
 * so what it can name was never the thing being defended.
 *
 * A too-large `toIndex` needs no handling: the walk stops at `data.length`, so
 * a range past the end is visited exactly as `fill` clamped it.
 */
function coverage(ranges: Window[]) {
	return mergeRanges(
		ranges.filter(r => r.fromIndex >= 0 && r.toIndex >= 0)
	)
}

/**
 * Congruence for one direction: revealed exactly where challenged, redacted
 * everywhere else. Windows drawn at random offsets can overlap, so this is
 * checked byte by byte rather than run by run. A one-sided check would let a
 * prover either hide a challenged byte or leak an unchallenged one.
 *
 * `proven` is where the claim says its ZK proofs land, checked against the
 * proofs themselves before the transcript was decrypted.
 *
 * Both sets used to be materialised as a `Uint8Array(data.length)` bitmap --
 * two more full-length copies of a transcript that can run to the 160 MiB
 * response ceiling, to answer a question that is about a handful of intervals.
 * They are sorted merged ranges now, and because `i` only ever moves forward, a
 * cursor per set answers the same question in constant space. The byte loop
 * itself has to stay: `looksRedacted` is a property of every individual byte.
 * `tokenswim-congruence-ranges.test.ts` keeps the bitmap version as an oracle.
 */
export function assertCongruent(
	direction: string,
	data: Uint8Array,
	windows: Window[],
	proven: Window[]
) {
	const challenged = coverage(windows)
	const covered = coverage(proven)

	// Cursors, not searches: both lists are sorted and disjoint and `i` is
	// monotonic, so each list is walked once across the whole loop. A range is
	// live for `i` when it has started and not yet ended; ranges that ended
	// before `i` are dropped and never looked at again.
	let ci = 0
	let vi = 0

	// Redaction is signalled by a sentinel byte that is also a legal payload
	// byte ('*'), so a revealed '*' and a redacted byte are indistinguishable
	// here. Outside a window the check stays strict, because leakage is
	// unambiguous. Inside one the byte has to be covered by a proof at least —
	// answering a challenge with no proof over it is the cheap forgery, and it
	// is the one this rules out.
	//
	// What is left after that is narrower and is not nothing: the prover is
	// asserting of each counted byte that its plaintext *is* `'*'`, and the ZK
	// verifier blanks the ciphertext wherever the plaintext says so, so no
	// proof was ever taken over it. That residue cannot be closed in this
	// representation, on either side — see ADR 0035.
	let ambiguous = 0
	for(let i = 0; i < data.length; i++) {
		while(ci < challenged.length && challenged[ci].toIndex <= i) {
			ci++
		}

		while(vi < covered.length && covered[vi].toIndex <= i) {
			vi++
		}

		const isChallenged = ci < challenged.length && challenged[ci].fromIndex <= i
		const isCovered = vi < covered.length && covered[vi].fromIndex <= i

		const looksRedacted = data[i] === REDACTION_CHAR_CODE
		if(isChallenged && looksRedacted) {
			if(!isCovered) {
				throw new Error(
					`${direction} byte ${i} was challenged and the claim proves nothing`
					+ ' over it'
				)
			}

			ambiguous++
			continue
		}

		if(!isChallenged && !looksRedacted) {
			throw new Error(`${direction} byte ${i} was revealed but never challenged`)
		}
	}

	return ambiguous
}

const MODEL_FIELD = /"model"\s*:\s*"([^"*]+)"/

/**
 * Reads the model out of the revealed client bytes.
 *
 * This is the load-bearing extracted field. Everything else in a claim says the
 * bytes are the bytes; only this says which model those bytes paid for, and
 * without it a cheaper model served against a dearer price stays inferred
 * rather than seen.
 *
 * Under HTTP/2 the client direction is SETTINGS, HPACK and DATA frames rather
 * than readable HTTP, but the DATA payload carries the JSON body raw, so the
 * field is still there to find. The JSON around it is redacted, so this cannot
 * decode the body the way the prover does — it matches the `"model": "…"` pair
 * inside a revealed run and takes the value, refusing a value with a redaction
 * byte in it as half-read.
 *
 * Read from the narrowest range the claim named, widening only when that fails:
 * the field the prover located exactly, then the chunk that had to be revealed
 * to carry it, then anything revealed at all.
 *
 * The order is the whole of the fix for a bug this had on its first end-to-end
 * run. A proof covers a whole circuit chunk, so the reveal is widened to chunk
 * boundaries — and the widening drags in whatever JSON sits next to the field.
 * When that neighbour is a tool schema's own `model` property, a search over the
 * chunk finds the decoy first and publishes it as the model that was billed. The
 * prover already knows the exact range, so it says where it is.
 *
 * That the ranges are prover-chosen is why this value is reported rather than
 * trusted — a prover pointing at a decoy on purpose is a known gap, answered by
 * a verifier reading the offsets, not by a stricter parse here. What is fixed is
 * the honest case, which was getting it wrong on its own.
 *
 * A claim whose model cannot be read is still a sound claim about the bytes, so
 * this says so in the parameters rather than throwing.
 */
export function extractModel(
	request: Uint8Array,
	modelField?: Window,
	modelChunk?: Window
) {
	const candidates: [Window | undefined, string][] = [
		[modelField, 'the revealed model field'],
		[modelChunk, 'the revealed model chunk'],
		[{ fromIndex: 0, toIndex: request.length }, 'a revealed challenge window'],
	]

	for(const [range, source] of candidates) {
		if(!range) {
			continue
		}

		// A range outside what was revealed reads as redaction bytes, which the
		// pattern refuses as a half-read value rather than matching them.
		const found = MODEL_FIELD.exec(
			uint8ArrayToStr(request.slice(range.fromIndex, range.toIndex))
		)
		if(found) {
			return { value: found[1], source }
		}
	}

	return { value: '', source: 'no readable model field in the revealed request bytes' }
}

const provider: Provider<'tokenswimWindow'> = {
	hostPort: ({ url }) => {
		const { host } = new URL(url)
		return host.includes(':') ? host : `${host}:443`
	},
	createRequest(_secret, params) {
		const url = new URL(params.url)
		const headers = Object.entries(params.headers ?? {})
			.map(([k, v]) => `${k}: ${v}`)
			.join('\r\n')
		const data = [
			`${params.method} ${url.pathname}${url.search} HTTP/1.1`,
			`Host: ${url.host}`,
			'Connection: close',
			headers,
			'',
			params.body ?? '',
		].join('\r\n')
		return { data, redactions: [] }
	},
	async assertValidProviderReceipt({ receipt, params }) {
		const request = concatenateUint8Arrays(
			receipt.filter(m => m.sender === 'client').map(m => m.message)
		)
		const response = concatenateUint8Arrays(
			receipt.filter(m => m.sender === 'server').map(m => m.message)
		)

		// A direction with no application data has nothing to challenge, and the
		// congruence loop would pass over an empty range. Refusing here is the
		// difference between a vacuous proof and a real one — and both
		// directions matter now, since the request is what names the model.
		if(!request.length) {
			throw new Error('no client application data in the receipt')
		}

		if(!response.length) {
			throw new Error('no server application data in the receipt')
		}

		// The other end of the bridge: `assertProvenRangesBindTheTranscript`
		// arrived at these same two numbers from the undecrypted transcript, so
		// agreeing here is what makes an offset mean the same byte at both ends.
		// Without it the proven ranges are checked in one coordinate system and
		// used in another, and the shift is the prover's to choose.
		if(request.length !== params.clientLength) {
			throw new Error(
				`the claim says the client direction carried ${params.clientLength}`
				+ ` bytes and the receipt holds ${request.length}`
			)
		}

		if(response.length !== params.serverLength) {
			throw new Error(
				`the claim says the server direction carried ${params.serverLength}`
				+ ` bytes and the receipt holds ${response.length}`
			)
		}

		const clientDigest = hexToBytes(params.clientDigest)
		const serverDigest = hexToBytes(params.serverDigest)
		const signatures = await assertWitnessesSawTheSameBytes(
			{
				routeSlotId: params.routeSlotId,
				transcriptRoot: hexToBytes(params.transcriptRoot),
				clientDigest,
				serverDigest,
				clientApplicationLen: params.clientApplicationLen,
				serverApplicationLen: params.serverApplicationLen,
				responseLeafCount: params.responseLeafCount,
			},
			params.witnesses
		)

		const clientWindows = await deriveWindows(
			signatures, clientDigest, 'c', request.length, params.windowCount
		)
		const serverWindows = await deriveWindows(
			signatures, serverDigest, 's', response.length, params.windowCount
		)

		// The model chunk is revealed on top of the challenged windows, so the
		// congruence check has to be told where it is: to a check that only
		// knows the derived windows, a reveal it did not challenge is a leak.
		const modelChunk = params.modelChunk
			? { fromIndex: params.modelChunk[0], toIndex: params.modelChunk[1] }
			: undefined
		const toWindows = (pairs: [number, number][]) => pairs.map(
			([fromIndex, toIndex]) => ({ fromIndex, toIndex })
		)
		const ambiguous = assertCongruent(
			'client',
			request,
			modelChunk ? [...clientWindows, modelChunk] : clientWindows,
			toWindows(params.clientProven)
		) + assertCongruent(
			'server', response, serverWindows, toWindows(params.serverProven)
		)

		// Only the chunk is congruence-checked: the field is a range inside it,
		// and naming one outside would not reveal a byte the chunk did not.
		const modelField = params.modelField
			? { fromIndex: params.modelField[0], toIndex: params.modelField[1] }
			: undefined
		const model = extractModel(request, modelField, modelChunk)
		const extractedParameters: { [key: string]: string } = {
			clientWindows: spell(clientWindows),
			serverWindows: spell(serverWindows),
			requestLength: String(request.length),
			responseLength: String(response.length),
			// In the order the offsets were seeded in, which is what a verifier
			// re-deriving them has to reproduce.
			witnesses: params.witnesses
				.map(w => w.publicKey!.toLowerCase())
				.sort()
				.join(','),
			witnessCount: String(params.witnesses.length),
			ambiguousBytes: String(ambiguous),
			model: model.value,
			modelSource: model.source,
			// Both published because the prover chose both: a verifier comparing
			// them against the derived windows is what closes the decoy gap above.
			modelChunk: modelChunk ? spell([modelChunk]) : '',
			modelField: modelField ? spell([modelField]) : '',
		}

		// Only the server's windows are published verbatim. The client's
		// revealed runs carry whatever HPACK put next to them, the Authorization
		// header included, and the claim context is public.
		serverWindows.forEach((w, i) => {
			extractedParameters[`window${i}`] = uint8ArrayToStr(
				response.slice(w.fromIndex, w.toIndex)
			)
		})

		return { extractedParameters }
	},
}

function spell(windows: Window[]) {
	return windows.map(w => `${w.fromIndex}-${w.toIndex}`).join(',')
}

function compareBytes(a: Uint8Array, b: Uint8Array) {
	for(let i = 0; i < Math.min(a.length, b.length); i++) {
		if(a[i] !== b[i]) {
			return a[i] - b[i]
		}
	}

	return a.length - b.length
}

function hexToBytes(hex: string) {
	return getBytes(hex.startsWith('0x') ? hex : `0x${hex}`)
}

export default provider
