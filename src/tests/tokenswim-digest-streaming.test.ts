import assert from 'node:assert'
import { describe, it } from 'node:test'

import { TranscriptMessageSenderType } from '#src/proto/api.ts'
import { assertDigestsBindTheTranscript } from '#src/providers/tokenswim-window/index.ts'

/**
 * `assertDigestsBindTheTranscript` used to join a direction into one
 * `Uint8Array` and hand it to `crypto.subtle.digest`, which has no streaming
 * API. At the 160 MiB response ceiling that copy was the largest single live
 * allocation on the claim path. It now folds the same bytes record by record.
 *
 * The digest value is what the Witness receipts are compared against, so it
 * must not move by a single byte. This file keeps the joined implementation as
 * an oracle and asserts the two agree — including on the shapes that a
 * streaming fold is most likely to get wrong: block boundaries, empty records,
 * and records that interleave with the other direction.
 */
type Message = { sender: unknown; message: Uint8Array }

/** The implementation being replaced, verbatim in its essentials. */
async function joinedDigest(transcript: Message[], side: 'client' | 'server') {
	const parts = transcript
		.filter(m => (
			m.sender === side
			|| m.sender === (side === 'client'
				? TranscriptMessageSenderType.TRANSCRIPT_MESSAGE_SENDER_TYPE_CLIENT
				: TranscriptMessageSenderType.TRANSCRIPT_MESSAGE_SENDER_TYPE_SERVER)
		))
		.map(m => m.message)

	const total = parts.reduce((n, p) => n + p.length, 0)
	const joined = new Uint8Array(total)
	let at = 0
	for(const p of parts) {
		joined.set(p, at)
		at += p.length
	}

	return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', joined))
}

/**
 * The new implementation only reports "equal" or "not equal", so it is driven
 * differentially: hand it the oracle's digest and it must accept, hand it that
 * digest with one bit moved and it must refuse. An implementation computing a
 * different digest fails the first; one that compares nothing fails the second.
 */
async function assertAgrees(transcript: Message[], what: string) {
	const client = await joinedDigest(transcript, 'client')
	const server = await joinedDigest(transcript, 'server')

	await assert.doesNotReject(
		() => assertDigestsBindTheTranscript(transcript, client, server),
		`${what}: streamed digest differs from the joined one`
	)

	for(const [name, bad] of [
		['client', [flip(client), server]],
		['server', [client, flip(server)]],
	] as const) {
		await assert.rejects(
			() => assertDigestsBindTheTranscript(transcript, bad[0], bad[1]),
			`${what}: a wrong ${name} digest was accepted`
		)
	}
}

function flip(digest: Uint8Array) {
	const out = Uint8Array.from(digest)
	out[out.length - 1] ^= 1
	return out
}

/** Deterministic, so a failure is reproducible without capturing the input. */
function makeRng(seed: number) {
	let s = seed >>> 0
	return () => {
		s = (s * 1664525 + 1013904223) >>> 0
		return s / 0x100000000
	}
}

function randomBytes(rng: () => number, n: number) {
	const out = new Uint8Array(n)
	for(let i = 0; i < n; i++) {
		out[i] = Math.floor(rng() * 256)
	}

	return out
}

const CLIENT = TranscriptMessageSenderType.TRANSCRIPT_MESSAGE_SENDER_TYPE_CLIENT
const SERVER = TranscriptMessageSenderType.TRANSCRIPT_MESSAGE_SENDER_TYPE_SERVER

describe('tokenswim digest: streaming equals joining', () => {
	it('agrees on the named shapes', async() => {
		const rng = makeRng(0x5eed)
		const named: [string, Message[]][] = [
			['one record each way', [
				{ sender: CLIENT, message: randomBytes(rng, 100) },
				{ sender: SERVER, message: randomBytes(rng, 100) },
			]],
			['single byte each way', [
				{ sender: CLIENT, message: Uint8Array.of(7) },
				{ sender: SERVER, message: Uint8Array.of(9) },
			]],
			// SHA-256 compresses 64 bytes at a time; a fold that mishandled its
			// buffer would show up first at and around that boundary.
			['records at the 64-byte block boundary', [
				{ sender: CLIENT, message: randomBytes(rng, 64) },
				{ sender: CLIENT, message: randomBytes(rng, 64) },
				{ sender: SERVER, message: randomBytes(rng, 63) },
				{ sender: SERVER, message: randomBytes(rng, 65) },
			]],
			['a record spanning many blocks', [
				{ sender: CLIENT, message: randomBytes(rng, 4096) },
				{ sender: SERVER, message: randomBytes(rng, 16384) },
			]],
			// An empty record must be a no-op, not a delimiter: if the fold let
			// one change the digest, a prover could pad a transcript freely.
			['empty records between real ones', [
				{ sender: CLIENT, message: randomBytes(rng, 30) },
				{ sender: CLIENT, message: new Uint8Array(0) },
				{ sender: CLIENT, message: randomBytes(rng, 30) },
				{ sender: SERVER, message: new Uint8Array(0) },
				{ sender: SERVER, message: randomBytes(rng, 30) },
			]],
			// Order within a direction is what the digest commits to, and the
			// two directions interleave arbitrarily on the wire.
			['heavily interleaved directions', Array.from({ length: 60 }, (_, i) => ({
				sender: i % 3 === 0 ? SERVER : CLIENT,
				message: randomBytes(rng, 1 + Math.floor(rng() * 200)),
			}))],
			// Both spellings of a sender reach this file; missing one would
			// filter every message out and bind nothing.
			['the string spelling of sender', [
				{ sender: 'client', message: randomBytes(rng, 50) },
				{ sender: 'server', message: randomBytes(rng, 50) },
			]],
			['both spellings mixed', [
				{ sender: 'client', message: randomBytes(rng, 10) },
				{ sender: CLIENT, message: randomBytes(rng, 10) },
				{ sender: 'server', message: randomBytes(rng, 10) },
				{ sender: SERVER, message: randomBytes(rng, 10) },
			]],
		]

		for(const [what, transcript] of named) {
			await assertAgrees(transcript, what)
		}
	})

	it('agrees on randomised transcripts', async() => {
		const rng = makeRng(0xc0ffee)
		for(let t = 0; t < 40; t++) {
			const count = 1 + Math.floor(rng() * 25)
			const transcript: Message[] = []
			let sawClient = false
			let sawServer = false
			for(let i = 0; i < count; i++) {
				const isClient = rng() < 0.5
				sawClient ||= isClient
				sawServer ||= !isClient
				transcript.push({
					sender: isClient ? CLIENT : SERVER,
					message: randomBytes(rng, Math.floor(rng() * 3000)),
				})
			}

			// A direction with no records is refused rather than digested, and
			// that path has its own test below.
			if(!sawClient) {
				transcript.push({ sender: CLIENT, message: randomBytes(rng, 8) })
			}

			if(!sawServer) {
				transcript.push({ sender: SERVER, message: randomBytes(rng, 8) })
			}

			await assertAgrees(transcript, `random transcript ${t}`)
		}
	})

	it('still refuses a direction with no records at all', async() => {
		// The client digest is checked first, so it has to be the right one for
		// the missing-server case to be the thing that fails.
		const clientOnly: Message[] = [{ sender: CLIENT, message: Uint8Array.of(1) }]
		const realClient = await joinedDigest(clientOnly, 'client')
		await assert.rejects(
			() => assertDigestsBindTheTranscript(
				clientOnly,
				realClient,
				new Uint8Array(32)
			),
			/no server messages/
		)

		await assert.rejects(
			() => assertDigestsBindTheTranscript(
				[{ sender: SERVER, message: Uint8Array.of(1) }],
				new Uint8Array(32),
				new Uint8Array(32)
			),
			/no client messages/
		)
	})

	it('does not treat a direction of only empty records as absent', async() => {
		// `seen` counts records, not bytes -- the old code tested `parts.length`
		// the same way. A direction of empty records has a digest (of nothing)
		// and must be compared against it rather than refused.
		const transcript: Message[] = [
			{ sender: CLIENT, message: new Uint8Array(0) },
			{ sender: SERVER, message: Uint8Array.of(1) },
		]
		await assertAgrees(transcript, 'client direction of only empty records')
	})
})
