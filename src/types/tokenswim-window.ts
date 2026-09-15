/**
 * The Tokenswim Relay Proof provider's parameters, hand-written on purpose.
 *
 * These used to live in `providers.gen.ts`, which `generate:provider-types`
 * truncates and rewrites from `provider-schemas/*` on every run -- so the block
 * survived only because nobody had run the generator since it was added. The
 * last change to those types was made by hand-editing the generated file,
 * which is the same bug one step earlier.
 *
 * Giving the provider a `provider-schemas/tokenswimWindow/` folder was the
 * obvious fix and is the wrong one: the generator compiles yaml with
 * `ignoreMinAndMaxItems`, so every `[from, to)` pair below comes back as
 * `number[]` -- a two-element tuple degraded to an unbounded array, on the
 * ranges that say which bytes a ZK proof actually covers -- and the prose that
 * explains why each field exists has nowhere to live in the schema. Round-trip
 * measured, not assumed.
 *
 * So the types stay hand-written and stay out of the generator's way. The two
 * halves are joined in `providers.ts`, which is the one place that knows which
 * providers exist.
 */

export interface TokenswimWindowParameters {
	url: string
	method: string
	headers?: { [k: string]: string }
	body?: string
	/** hex digest of the client direction's ciphertext, the seed for its windows */
	clientDigest: string
	/** hex digest of the server direction's ciphertext */
	serverDigest: string
	windowCount: number
	/**
	 * How many bytes of application data each direction carried. Named rather
	 * than only derived because the claim path arrives at it twice — once from
	 * the undecrypted transcript and once from the decrypted receipt — and the
	 * proven ranges below mean the same bytes at both ends only when the two
	 * agree.
	 */
	clientLength: number
	serverLength: number
	/**
	 * The [from, to) ranges of each direction's application data that a ZK proof
	 * covers, in the same coordinates as the challenge windows. Sorted, with
	 * touching ranges fused. Redaction is marked with a byte that is also legal
	 * data, so this is what says a challenged byte was answered with a proof at
	 * all rather than with the sentinel.
	 */
	clientProven: [number, number][]
	serverProven: [number, number][]
	/**
	 * Every Witness in the relay path, each with its BLS12-381 public key and
	 * its signature over SHA-256(clientDigest ‖ serverDigest). At least two, all
	 * distinct; the protocol sets no upper bound, so this is a list rather than
	 * a fixed pair of fields.
	 */
	witnesses: {
		publicKey: string
		signature: string
	}[]
	/**
	 * The rest of what each Witness signature covers. A receipt commits to the
	 * route slot, the transcript root, both digests, both application lengths
	 * and the response leaf count under a domain tag -- seven fields, of which
	 * the two digests above are two. Without these five a verifier cannot
	 * rebuild the message that was signed, so it can check nothing.
	 */
	routeSlotId: number
	/** hex, 32 bytes: the Merkle root over the server-direction leaves */
	transcriptRoot: string
	clientApplicationLen: number
	serverApplicationLen: number
	responseLeafCount: number
	/**
	 * [from, to) over the client direction, revealed on top of the challenged
	 * windows because it names the model. Absent when the request named none.
	 */
	modelChunk?: [number, number]
	/**
	 * [from, to) of the `"model": value` pair itself, inside modelChunk. The
	 * chunk is what had to be revealed; this is where to read, because widening
	 * to chunk boundaries can drag a tool schema's own `model` in beside it.
	 */
	modelField?: [number, number]
}

export const TokenswimWindowParametersJson = {
	title: 'TokenswimWindowParameters',
	type: 'object',
	properties: {
		url: { type: 'string' },
		method: { type: 'string' },
		headers: { type: 'object', additionalProperties: { type: 'string' } },
		body: { type: 'string' },
		clientDigest: { type: 'string' },
		serverDigest: { type: 'string' },
		windowCount: { type: 'number' },
		clientLength: { type: 'number' },
		serverLength: { type: 'number' },
		clientProven: {
			type: 'array',
			items: {
				type: 'array', items: { type: 'number' }, minItems: 2, maxItems: 2,
			},
		},
		serverProven: {
			type: 'array',
			items: {
				type: 'array', items: { type: 'number' }, minItems: 2, maxItems: 2,
			},
		},
		witnesses: {
			type: 'array',
			minItems: 2,
			items: {
				type: 'object',
				properties: {
					publicKey: { type: 'string' },
					signature: { type: 'string' },
				},
				required: ['publicKey', 'signature'],
				additionalProperties: false,
			},
		},
		routeSlotId: { type: 'number' },
		transcriptRoot: { type: 'string' },
		clientApplicationLen: { type: 'number' },
		serverApplicationLen: { type: 'number' },
		responseLeafCount: { type: 'number' },
		modelChunk: {
			type: 'array', items: { type: 'number' }, minItems: 2, maxItems: 2,
		},
		modelField: {
			type: 'array', items: { type: 'number' }, minItems: 2, maxItems: 2,
		},
	},
	required: [
		'url', 'method', 'clientDigest', 'serverDigest', 'windowCount', 'witnesses',
		'clientLength', 'serverLength', 'clientProven', 'serverProven',
		'routeSlotId', 'transcriptRoot', 'clientApplicationLen',
		'serverApplicationLen', 'responseLeafCount',
	],
	additionalProperties: false,
}

export const TokenswimWindowSecretParametersJson = {
	title: 'TokenswimWindowSecretParameters',
	type: 'object',
	properties: {},
	additionalProperties: false,
}
