import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { createHash } from 'node:crypto'
import { getBytes } from 'ethers'

import { ETH_SIGNATURE_PROVIDER } from '#src/utils/signatures/eth.ts'

const DOMAIN = Buffer.from('TOKENSWIM_NET_ATTESTATION_V1\0', 'ascii')
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
	for(const [from, to] of ranges) {
		parts.push(u64(from), u64(to))
	}
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
	upstreamHost: string
	model: string
	owner: string
}

function publicAttestationDigest(f: PublicFacts) {
	const clientDigest = getBytes(f.clientDigest)
	const serverDigest = getBytes(f.serverDigest)
	assert.equal(clientDigest.length, 32)
	assert.equal(serverDigest.length, 32)

	const proven = sha256(Buffer.concat([
		Buffer.from(rangesHash(f.clientProven)),
		Buffer.from(rangesHash(f.serverProven)),
	]))
	const preimage = Buffer.concat([
		DOMAIN,
		u32(1),
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
	])
	return { preimage, digest: sha256(preimage) }
}

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
	upstreamHost: 'chatgpt.com',
	model: 'gpt-5-codex',
	owner: '0xffcf8fdee72ac11b5c542428b35eef5769c409f0',
}

test('public attestation is fixed-size, secret-free, signed, and mutation-bound', async () => {
	const { preimage, digest } = publicAttestationDigest(facts)
	const forbidden = [
		'/backend-api/codex/responses?secret=never-publish',
		'Authorization',
		'Bearer ',
		'raw plaintext context',
	]
	const text = preimage.toString('latin1')
	for(const secret of forbidden) assert.equal(text.includes(secret), false)

	// Domain(29) + version(4) + timestamp(8) + 2 digests(64) + witness hash(32)
	// + lengths(16) + window count(4) + four final hashes(128) = 285 bytes.
	assert.equal(preimage.length, 285)
	assert.equal(digest.length, 32)

	const publicKey = ETH_SIGNATURE_PROVIDER.getPublicKey(PRIVATE_KEY)
	const address = ETH_SIGNATURE_PROVIDER.getAddress(publicKey)
	const signature = await ETH_SIGNATURE_PROVIDER.sign(digest, PRIVATE_KEY)
	assert.equal(await ETH_SIGNATURE_PROVIDER.verify(digest, signature, address), true)

	const mutated = publicAttestationDigest({ ...facts, model: 'gpt-5-codex-forged' }).digest
	assert.equal(await ETH_SIGNATURE_PROVIDER.verify(mutated, signature, address), false)

	console.log(`TOKENSWIM_PUBLIC_ATTESTATION_VECTOR digest=0x${Buffer.from(digest).toString('hex')} address=${address} signature=0x${Buffer.from(signature).toString('hex')}`)
})
