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
// as a single ClaimTunnelRequest over this same socket.
//
// What that message can weigh is a formula, not a constant to copy here.
// The transcript is wire bytes, so its ceiling is
// `transcript.MaxLeaves * (MaxChunkBytes + record overhead)`
// (packages/proof-protocol/transcript/tree.go and partition.go). A TLS 1.3
// record costs 22 bytes around its body -- 5 header, 16 GCM tag, 1 inner
// content type -- and the worst case is one record per leaf, so the widest
// leaf costs 64 + 22 = 86 wire bytes. At the leaf ceiling this build ships
// that is about 215 MiB, plus a per-record reveal key and protobuf framing
// on top, against the 512 MiB below.
//
// Written as the formula deliberately: a number here would be stale the
// moment MaxLeaves moved, and it has moved once already. Do not size this
// off `MaxPayloadBytesCeiling` or `MaxPrivateArtifactBytes` either -- the
// version of this comment that did was wrong in a way that read as
// reassuring, because neither of those bounds this message. One is a policy
// ceiling on *plaintext* response bytes and the other bounds a JSON artifact
// that never crosses this socket; the transcript is ciphertext plus record
// framing, and it is larger than both.
//
// Without `maxPayload` set at all, `ws` falls back to its own undocumented
// 100MB default -- under the ceiling above, so a large session would have
// been dropped at the socket with no error worth reading.
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
