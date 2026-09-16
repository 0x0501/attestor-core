import '#src/server/utils/config-env.ts'

import { setCryptoImplementation } from '@reclaimprotocol/tls'
import { webcryptoCrypto } from '@reclaimprotocol/tls/webcrypto'

import { getApm } from '#src/server/utils/apm.ts'
import { logger as LOGGER } from '#src/utils/logger.ts'
getApm()

setCryptoImplementation(webcryptoCrypto)

/**
 * Keeps a throw that reached nobody from taking the sessions that had nothing
 * to do with it.
 *
 * Node's default for an uncaught exception is to end the process. For most
 * programs that is right. This one is holding live TLS tunnels: every session
 * mid-flight loses its transcript, and the relay on the other side of :8001
 * sees `write: broken pipe` and files a rejection for a proof that was fine.
 * On 2026-09-15 a WebSocket in the BGP hijack listener -- an auxiliary feed
 * from a third party, nothing to do with any session -- threw
 * InvalidStateError out of its open handler, and seven proofs died with it.
 *
 * So the trade is made explicitly and in this direction: log it as fatal, keep
 * serving. That is not free. An exception nobody handled may have left state
 * half-written, and a process that continues past one can do something worse
 * than stop. What makes it the better side of the trade here is that the
 * alternative is not "stop safely" -- it is "lose every proof in flight,
 * every time, including the ones caused by a feed we do not control". A
 * session that is actually broken by this fails on its own, loudly, and only
 * itself.
 */
function guardProcess() {
	process.on('uncaughtException', (err, origin) => {
		LOGGER.fatal({ err, origin }, 'uncaught exception; the attestor is staying up')
	})

	process.on('unhandledRejection', (err) => {
		LOGGER.fatal({ err }, 'unhandled rejection; the attestor is staying up')
	})
}

async function main() {
	// importing dynamically to allow APM to inject
	// into modules before they are used
	const { createServer } = await import('#src/server/index.ts')
	guardProcess()
	return createServer()
}

main()