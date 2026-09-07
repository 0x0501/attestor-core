import type { InitRequest } from '#src/proto/api.ts'
import { AttestorVersion, ServiceSignatureType } from '#src/proto/api.ts'

export const DEFAULT_ZK_CONCURRENCY = 10

export const RECLAIM_USER_AGENT = 'reclaim/0.0.1'

export const DEFAULT_HTTPS_PORT = 443

export const WS_PATHNAME = '/ws'

export const BROWSER_RPC_PATHNAME = '/browser-rpc'

export const ATTESTOR_ADDRESS_PATHNAME = '/address'

export const DEFAULT_REMOTE_FILE_FETCH_BASE_URL = `${BROWSER_RPC_PATHNAME}/resources`

export const API_SERVER_PORT = 8001

// 10s
export const CONNECTION_TIMEOUT_MS = 10_000

export const DNS_SERVERS = [
	'8.8.8.8',
	'8.8.4.4'
]

// 10m
export const MAX_CLAIM_TIMESTAMP_DIFF_S = 10 * 60

export const CURRENT_ATTESTOR_VERSION = AttestorVersion.ATTESTOR_VERSION_3_2_0

export const DEFAULT_METADATA: InitRequest = {
	signatureType: ServiceSignatureType.SERVICE_SIGNATURE_TYPE_ETH,
	clientVersion: CURRENT_ATTESTOR_VERSION,
	auth: undefined
}

export const PROVIDER_CTX = { version: CURRENT_ATTESTOR_VERSION }

export const PING_INTERVAL_MS = 10_000
/**
 * Maximum interval in seconds to wait for before assuming
 * the connection is dead
 * @default 30s
 */
export const MAX_NO_DATA_INTERVAL_MS = 30_000

// Passed as `maxPayload` when the WebSocketServer is constructed
// (src/server/create-server.ts). Sized for `claimTunnel`, not for the
// tunnel-chunk stream: relay's submitClaim
// (apps/relay/internal/relayserver/proven.go) hands Client.ClaimTunnel the
// *whole* session transcript in one message -- Transcript.Messages()
// (apps/relay/internal/relay/transcript.go) walks every entry in both
// directions, ciphertext plus per-record reveal keys, and relay ships that
// as a single ClaimTunnelRequest over this same socket. The chain's own
// ceilings on that transcript are already tens of MiB before framing and
// reveal overhead (MaxPayloadBytesCeiling = 32 MiB response bytes,
// apps/net/x/provider/types/params.go; MaxPrivateArtifactBytes = 64 MiB,
// packages/proof-protocol/validate/validate.go) and grow if either is
// raised, so this is headroom for a whole-session upload, not a chunk.
// Without it `ws` falls back to its own undocumented 100MB default, which a
// large session could silently exceed.
//
// Asymmetric with relay's own receive side
// (apps/relay/internal/attestor/client.go): that reads individual
// TunnelMessage frames streamed back from the attestor in the *other*
// direction, each one upstream TCP read/TLS record and orders of magnitude
// smaller. Different job, different number -- don't size the two off each
// other.
export const MAX_PAYLOAD_SIZE = 512 * 1024 * 1024 // 512MB

export const DEFAULT_AUTH_EXPIRY_S = 15 * 60 // 15m

export const DEFAULT_RPC_TIMEOUT_MS = 90_000

export const TOPRF_DOMAIN_SEPARATOR = 'reclaim-toprf'

export const MAX_CERT_SIZE_BYTES = 10 * 1024 * 1024 // 10MB

export const CERT_ALLOWED_MIMETYPES = [
	'application/x-x509-ca-cert',
	'application/x-x509-user-cert',
	'application/pkix-cert',
	'application/pkcs7-mime',
	'application/octet-stream'
]

export const BGP_WS_URL = 'wss://ris-live.ripe.net/v1/ws/?client=reclaim-hijack-detector'
