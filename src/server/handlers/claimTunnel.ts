import { MAX_CLAIM_TIMESTAMP_DIFF_S } from '#src/config/index.ts'
import { ClaimTunnelResponse } from '#src/proto/api.ts'
import { getApm } from '#src/server/utils/apm.ts'
import { assertTranscriptsMatch, assertValidClaimRequest } from '#src/server/utils/assert-valid-claim-request.ts'
import { getAttestorAddress, signAsAttestor } from '#src/server/utils/generics.ts'
import type { RPCHandler } from '#src/types/index.ts'
import {
	AttestorError,
	createSignDataForClaim,
	getIdentifierFromClaimInfo,
	unixTimestampSeconds
} from '#src/utils/index.ts'

export const claimTunnel: RPCHandler<'claimTunnel'> = async(
	claimRequest,
	{ tx, logger, client }
) => {
	const {
		request,
		data: { timestampS } = {},
	} = claimRequest
	// TOKENSWIM OVERLAY — the one place in it that *relaxes* an upstream check.
	// The other eight files strengthen or extend; this one lets a claim through
	// that upstream refuses outright, so it gets the longest comment in the
	// overlay. ADR 0040 is the argument, and the short form is: the thing being
	// skipped was never what bound a claim.
	//
	// Upstream resolves the tunnel with `client.getTunnel(request?.id!)`, which
	// throws `AttestorError('ERROR_NOT_FOUND')` when this websocket did not
	// create that tunnel. So a proof re-derived in another process — from
	// spooled material, hours later, on a host that has the ZK circuits — cannot
	// be counter-signed at all, and the whole spool-and-pull path is dead code.
	// ADR 0035 asserts both "any node can re-derive" and "the attestor is the
	// gate"; until this, those were not simultaneously satisfiable.
	//
	// Why it is not a weakening. The three checks below compare the claim
	// against *this attestor's own recording* of the session. ADR 0036
	// establishes that an observer Tokenswim operates proves nothing to anyone,
	// and the attestor is one — so agreement with it is not evidence, it is
	// self-agreement. What binds a claim is `assertValidClaimRequest`, which
	// recomputes both ciphertext digests from the transcript the claim carries
	// and refuses a claim naming any other (ADR 0040). Those digests are what
	// the Witnesses — parties that are not the prover and not us — signed, and
	// they are the seed the challenge windows are drawn from. That binding is
	// strictly stronger than "the bytes our own attestor recorded", and it runs
	// on both paths. A tunnelled claim keeps the comparison as a cheap
	// consistency check on a path where it is free; it is not the binding.
	//
	// What a deferred claim gives up, named rather than glossed: `port`,
	// `geoLocation` and `proxySessionId` are compared against nothing else, and
	// on this path are not checked at all. `host` survives by another route —
	// `processHandshake` takes the hostname from the ClientHello's SNI inside
	// the claim's own transcript and validates the certificate chain against it,
	// and `assertValidClaimRequest` then refuses a claim whose stated host
	// disagrees. None of the three losses is evidentiary today (the certificate
	// binds the identity, not the port), but `proxySessionId` is what routes a
	// session through the Witness chain: if a reader is ever meant to check it,
	// it needs a binding of its own rather than the tunnel's memory of it.
	//
	// Absence is read off the map rather than by catching the throw. `getTunnel`
	// is a map lookup and a `throw` — there is no other failure it can report —
	// so `client.tunnels[id]` being undefined is the same fact without an
	// exception to classify, and it cannot mistake a genuine error for a missing
	// tunnel because a map read has no genuine errors to mistake.
	const tunnel = client.tunnels[request?.id!]
	if(tunnel) {
		try {
			await tunnel.close()
		} catch(err) {
			logger.debug({ err }, 'error closing tunnel')
		}

		if(tx) {
			const transcriptBytes = tunnel.transcript.reduce(
				(acc, { message }) => acc + message.length,
				0
			)
			tx?.setLabel('transcriptBytes', transcriptBytes.toString())
		}

		// we throw an error for cases where the attestor cannot prove
		// the user's request is faulty. For eg. if the user sends a
		// "createRequest" that does not match the tunnel's actual
		// create request -- the attestor cannot prove that the user
		// is lying. In such cases, we throw a bad request error.
		// Same goes for matching the transcript.
		if(
			tunnel.createRequest?.host !== request?.host
			|| tunnel.createRequest?.port !== request?.port
			|| tunnel.createRequest?.geoLocation !== request?.geoLocation
			|| tunnel.createRequest?.proxySessionId !== request?.proxySessionId
		) {
			throw AttestorError.badRequest('Tunnel request does not match')
		}

		assertTranscriptsMatch(claimRequest.transcript, tunnel.transcript)
	} else {
		logger.info(
			{ tunnelId: request?.id },
			'no tunnel on this connection: claiming from the transcript alone'
		)
	}

	const res = ClaimTunnelResponse.create({ request: claimRequest })
	try {
		const now = unixTimestampSeconds()
		if(Math.floor(timestampS! - now) > MAX_CLAIM_TIMESTAMP_DIFF_S) {
			throw new AttestorError(
				'ERROR_INVALID_CLAIM',
				`Timestamp provided ${timestampS} is too far off. Current time is ${now}`
			)
		}

		const assertTx = getApm()
			?.startTransaction('assertValidClaimRequest', { childOf: tx })

		try {
			const claim = await assertValidClaimRequest(
				claimRequest,
				client.metadata,
				logger
			)
			res.claim = {
				...claim,
				identifier: getIdentifierFromClaimInfo(claim),
				// hardcode for compatibility with V1 claims
				epoch: 1
			}
		} catch(err) {
			assertTx?.setOutcome('failure')
			throw err
		} finally {
			assertTx?.end()
		}
	} catch(err) {
		logger.error({ err }, 'invalid claim request')
		const attestorErr = AttestorError.fromError(err, 'ERROR_INVALID_CLAIM')
		res.error = attestorErr.toProto()
	}

	// Strip transcript before signing -- client already has it.
	// Reduces response size dramatically for STARK proofs.
	if(res.request) {
		res.request.transcript = []
	}

	res.signatures = {
		attestorAddress: getAttestorAddress(
			client.metadata.signatureType
		),
		claimSignature: res.claim
			? await signAsAttestor(
				createSignDataForClaim(res.claim),
				client.metadata.signatureType
			)
			: new Uint8Array(),
		resultSignature: await signAsAttestor(
			ClaimTunnelResponse.encode(res).finish(),
			client.metadata.signatureType
		)
	}

	// remove tunnel from client -- to free up our mem
	// (nothing to free on the deferred path -- there was never a tunnel here.
	// `request` is re-tested because upstream's only proof that it is defined
	// here was the createRequest comparison above, which the deferred path
	// skips: the compiler notices the loss before a reader does.)
	if(tunnel && request) {
		client.removeTunnel(request.id)
	}

	return res
}