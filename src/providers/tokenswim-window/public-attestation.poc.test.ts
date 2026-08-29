import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { createHash } from 'node:crypto'
import { getBytes } from 'ethers'

import { ClaimTunnelResponse } from '#src/proto/api.ts'
import { ETH_SIGNATURE_PROVIDER } from '#src/utils/signatures/eth.ts'

const DOMAIN = Buffer.from('TOKENSWIM_NET_ATTESTATION_V2\0', 'ascii')
const PROOF_BUNDLE_DOMAIN = Buffer.from('TOKENSWIM_PROOF_BUNDLE_V1\0', 'ascii')
const LEAF_RESULT_ROOT_DOMAIN = Buffer.from('TOKENSWIM_LEAF_RESULT_ROOT_V1\0', 'ascii')
const PRIVATE_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'

function sha256(data: Uint8Array | string) {
	return new Uint8Array(createHash('sha256').update(data).digest())
}

function u32(n: number) {
	const b = Buffer.alloc(4)
	b.writeUInt32BE(n)
	return b
}

function u64(n: number) {
	const b = Buffer.alloc(8)
	b.writeBigUInt64BE(BigInt(n))
	return b
}

function rangesHash(ranges: [number, number][]) {
	const parts: Uint8Array[] = [u32(ranges.length)]
	for(const [from, to] of ranges) parts.push(u64(from), u64(to))
	return sha256(Buffer.concat(parts.map(Buffer.from)))
}

function witnessSetHash(witnesses: { publicKey: string; signature: string }[]) {
	const ordered = [...witnesses].sort((a, b) => a.publicKey.localeCompare(b.publicKey))
	const parts: Uint8Array[] = [u32(ordered.length)]
	for(const w of ordered) {
		const key = getBytes(w.publicKey)
		const sig = getBytes(w.signature)
		assert.equal(key.length, 48)
		assert.equal(sig.length, 96)
		parts.push(key, sig)
	}
	return sha256(Buffer.concat(parts.map(Buffer.from)))
}

/**
 * Production computes this over a deterministic TokenswimProofBundleV1 whose
 * private body contains the canonical ClaimTunnelRequest plus the leaf receipts
 * that produced its chunks. The public chain receives only this 32-byte hash.
 */
function proofBundleHash(encodedProofBundle: Uint8Array) {
	return sha256(Buffer.concat([
		PROOF_BUNDLE_DOMAIN,
		Buffer.from(encodedProofBundle),
	]))
}

/**
 * Production uses a deterministic Merkle root of the public-safe leaf receipts
 * (task id, circuit id, public-input hash, proof hash, prover account/signature),
 * never the plaintext public inputs themselves. The fixed fixture below proves
 * the attestation actually binds this independent settlement commitment.
 */
function leafResultRoot(encodedLeafReceiptFixture: Uint8Array) {
	return sha256(Buffer.concat([
		LEAF_RESULT_ROOT_DOMAIN,
		Buffer.from(encodedLeafReceiptFixture),
	]))
}

type PublicFacts = {
	timestampS: number
	clientDigest: string
	serverDigest: string
	clientLength: number
	serverLength: number
	windowCount: number
	witnesses: { publicKey: string; signature: string }[]
	clientProven: [number, number][]
	serverProven: [number, number][]
	provider: string
	upstreamHost: string
	model: string
	owner: string
	proofBundleHash: Uint8Array
	leafResultRoot: Uint8Array
	circuitSetVersion: string
}

function publicAttestationDigest(f: PublicFacts) {
	const clientDigest = getBytes(f.clientDigest)
	const serverDigest = getBytes(f.serverDigest)
	assert.equal(clientDigest.length, 32)
	assert.equal(serverDigest.length, 32)
	assert.equal(f.proofBundleHash.length, 32)
	assert.equal(f.leafResultRoot.length, 32)

	const proven = sha256(Buffer.concat([
		Buffer.from(rangesHash(f.clientProven)),
		Buffer.from(rangesHash(f.serverProven)),
	]))
	const preimage = Buffer.concat([
		DOMAIN,
		u32(2),
		u64(f.timestampS),
		Buffer.from(clientDigest),
		Buffer.from(serverDigest),
		Buffer.from(witnessSetHash(f.witnesses)),
		u64(f.clientLength),
		u64(f.serverLength),
		u32(f.windowCount),
		Buffer.from(proven),
		Buffer.from(sha256(f.upstreamHost.toLowerCase())),
		Buffer.from(sha256(f.model)),
		Buffer.from(sha256(f.owner.toLowerCase())),
		Buffer.from(sha256(f.provider)),
		Buffer.from(f.proofBundleHash),
		Buffer.from(f.leafResultRoot),
		Buffer.from(sha256(f.circuitSetVersion)),
	])
	return { preimage, digest: sha256(preimage) }
}

const encodedProofBundleFixture = Buffer.from(
	'TokenswimProofBundleV1 deterministic protobuf fixture: ClaimTunnelRequest + signed leaf receipts',
	'utf8',
)
const encodedLeafReceiptFixture = Buffer.from(
	'leaf-0|chacha20|public-input-hash|proof-hash|tokenswim1prover|signature',
	'utf8',
)

const facts: PublicFacts = {
	timestampS: 1756300000,
	clientDigest: '0x3df0e09ac3f7e866fbf6b8ac112d896391d119693d94e7af9ea9ef197b629e31',
	serverDigest: '0x873e0c127eaff838fbefc029b1096455d8fe2a012b2d535572790e17714475fb',
	clientLength: 856,
	serverLength: 4096,
	windowCount: 3,
	witnesses: [
		{
			publicKey: '0x942721bfb54938c4e8cea88e26b20310a4b04bfab8fe0f35de26d493b47b738bfd5229778664effc705d9d28cf8b6627',
			signature: '0xa30e67c9cf00e8e16315d06a26f43922a55f564f2355e0d9e71c057643ef70278f9198cc475c0a1edc691ed62b9c3a070bd63177060f8e88e8e315bc116201aabe025c69ed8d35f8801cfc975a39548453a5fbfe0d0ef44ede66707a0fa059c3',
		},
		{
			publicKey: '0x9850b280487cf5ec36b3b208a2678d76c14aecedfe3877aa4b61fc1a4ae636f0bc9ce37602ae2ffe8c8e6e8c86028ad8',
			signature: '0xb6e898861563efc8fc2686a2dcf7196f69f4ec0dd150475d0af5fc63b06e46fc2731e853534b808ba2e823760f1ab81607702240f1d6f57cc4a792ac90f3aeb8a7915627391ff23bf9181969e76d99431e1bd8a5548760a86314e51ec8aa956e',
		},
	],
	clientProven: [[0, 896]],
	serverProven: [[2432, 3200]],
	provider: 'tokenswimWindow',
	upstreamHost: 'chatgpt.com',
	model: 'gpt-5-codex',
	owner: '0xffcf8fdee72ac11b5c542428b35eef5769c409f0',
	proofBundleHash: proofBundleHash(encodedProofBundleFixture),
	leafResultRoot: leafResultRoot(encodedLeafReceiptFixture),
	circuitSetVersion: 'reclaim-gnark-v0.14.0/chacha20@40c74b9e1c9f',
}

test('public attestation V2 is fixed-size, secret-free, signed, bundle-bound, and leaf-bound', async () => {
	const { preimage, digest } = publicAttestationDigest(facts)
	const forbidden = [
		'/backend-api/codex/responses?secret=never-publish',
		'Authorization',
		'Bearer ',
		'raw plaintext context',
		encodedProofBundleFixture.toString('utf8'),
		encodedLeafReceiptFixture.toString('utf8'),
	]
	const text = preimage.toString('latin1')
	for(const secret of forbidden) assert.equal(text.includes(secret), false)

	// V1 was 285 bytes. V2 adds providerHash, proofBundleHash,
	// leafResultRoot, and circuitSetHash: four fixed 32-byte commitments.
	assert.equal(preimage.length, 413)
	assert.equal(digest.length, 32)

	const publicKey = ETH_SIGNATURE_PROVIDER.getPublicKey(PRIVATE_KEY)
	const address = ETH_SIGNATURE_PROVIDER.getAddress(publicKey)
	const signature = await ETH_SIGNATURE_PROVIDER.sign(digest, PRIVATE_KEY)
	assert.equal(await ETH_SIGNATURE_PROVIDER.verify(digest, signature, address), true)

	for(const mutated of [
		publicAttestationDigest({ ...facts, model: 'gpt-5-codex-forged' }).digest,
		publicAttestationDigest({ ...facts, provider: 'otherProvider' }).digest,
		publicAttestationDigest({
			...facts,
			proofBundleHash: proofBundleHash(Buffer.from('different valid proof bundle', 'utf8')),
		}).digest,
		publicAttestationDigest({
			...facts,
			leafResultRoot: leafResultRoot(Buffer.from('different leaf receipts', 'utf8')),
		}).digest,
		publicAttestationDigest({
			...facts,
			circuitSetVersion: 'different-circuit-version',
		}).digest,
	]) {
		assert.equal(await ETH_SIGNATURE_PROVIDER.verify(mutated, signature, address), false)
	}

	console.log(`TOKENSWIM_PUBLIC_ATTESTATION_V2_VECTOR digest=0x${Buffer.from(digest).toString('hex')} bundle_hash=0x${Buffer.from(facts.proofBundleHash).toString('hex')} leaf_root=0x${Buffer.from(facts.leafResultRoot).toString('hex')} address=${address} signature=0x${Buffer.from(signature).toString('hex')}`)
})

function encodeVarint(value: number) {
	const out: number[] = []
	let n = value
	while(n >= 0x80) {
		out.push((n & 0x7f) | 0x80)
		n = Math.floor(n / 128)
	}
	out.push(n)
	return Uint8Array.from(out)
}

test('current TypeScript ClaimTunnelResponse ignores additive public-attestation field 5', () => {
	const legacy = ClaimTunnelResponse.encode(ClaimTunnelResponse.create({
		claim: {
			provider: 'tokenswim-window',
			owner: facts.owner,
			timestampS: facts.timestampS,
			identifier: 'claim-id',
		},
		signatures: {
			attestorAddress: '0x70997970c51812dc3a010c7d01b50e0d17dc79c8',
			claimSignature: Uint8Array.from([1, 2, 3]),
			resultSignature: Uint8Array.from([4, 5, 6]),
		},
	})).finish()

	const publicAttestation = new Uint8Array(413).fill(0xa5)
	const newerWire = Buffer.concat([
		Buffer.from(legacy),
		Buffer.from([0x2a]), // field 5, wire type 2
		Buffer.from(encodeVarint(publicAttestation.length)),
		Buffer.from(publicAttestation),
	])

	const decoded = ClaimTunnelResponse.decode(newerWire)
	assert.equal(decoded.claim?.provider, 'tokenswim-window')
	assert.equal(decoded.claim?.identifier, 'claim-id')
	assert.equal(decoded.signatures?.attestorAddress, '0x70997970c51812dc3a010c7d01b50e0d17dc79c8')
	assert.deepEqual(decoded.signatures?.claimSignature, Uint8Array.from([1, 2, 3]))
})