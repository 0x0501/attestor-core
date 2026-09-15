/**
 * Tokenswim: the far end of a routed session -- one Witness and the upstream it
 * dials -- in a process of its own.
 *
 * Out of process on purpose, and it is the whole reason the test around it
 * works. The defect it exists to catch is that the attestor used to discard
 * bytes the kernel had already accepted but Node had not yet emitted as
 * 'data', and the only way to hold a test inside that window is to stop the
 * attestor's event loop from turning. A Witness sharing that loop would stop
 * forwarding at the same instant, and there would be nothing buffered to lose.
 *
 * It speaks only node builtins. Nothing here may import from `#src`: this file
 * is forked with a bare `execArgv`, without the test runner's loader flags.
 */
import { type AddressInfo, connect, createServer, type Socket } from 'node:net'

/** What the upstream answers with, in a single write. */
const PAYLOAD_BYTES = 512 * 1024

/** What the Witness would put its name to, and what it saw asked of it. */
const report = { forwarded: 0, connectHead: '' }

/**
 * The upstream. Answers once and then holds the connection open forever,
 * because that is the shape that produced the bug: chatgpt.com serves an SSE
 * response over HTTP/2 and has no reason to close an idle connection
 * afterwards, so nothing upstream ever prompts this socket to end.
 */
const upstream = createServer(socket => {
	socket.on('error', () => {})
	socket.once('data', () => {
		socket.write(Buffer.alloc(PAYLOAD_BYTES, 0x61))
	})
})

/**
 * The Witness. A plain CONNECT relay that accounts for what it *forwards*,
 * counting a chunk only once the write has come back without an error -- the
 * same moment `apps/net/internal/witness/route`'s pipe hashes one, which is
 * after `Write` has returned and the kernel has taken the bytes.
 *
 * That is the accounting the bug contradicted: these bytes are inside the
 * account every seat on the route signs, whether or not the far end ever
 * reads them.
 */
const witness = createServer({ allowHalfOpen: true }, client => {
	client.on('error', () => {})
	client.once('data', head => {
		report.connectHead = head.toString('utf8')

		const target = /^CONNECT (\S+):(\d+)/.exec(report.connectHead)
		if(!target) {
			client.destroy()
			return
		}

		const up: Socket = connect(Number(target[2]), target[1], () => {
			client.write('HTTP/1.1 200 Connection established\r\n\r\n')
			client.on('data', data => up.write(data))
			up.on('data', data => (
				client.write(data, err => {
					if(!err) {
						report.forwarded += data.length
					}
				})
			))
		})
		up.on('error', () => {})
	})
})

const listen = (server: typeof upstream) => new Promise<number>(resolve => (
	server.listen(0, '127.0.0.1', () => (
		resolve((server.address() as AddressInfo).port)
	))
))

const upstreamPort = await listen(upstream)
const witnessPort = await listen(witness)

process.on('message', message => {
	if(message === 'report') {
		process.send!({ type: 'report', ...report })
	}
})

process.send!({
	type: 'ready',
	upstreamPort,
	witnessPort,
	payloadBytes: PAYLOAD_BYTES
})
