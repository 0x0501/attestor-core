import type { CreateTunnelRequest } from '#src/proto/api.ts'
import type { IAttestorClient, MakeTunnelFn, RPCEvent } from '#src/types/index.ts'
import { AttestorError } from '#src/utils/index.ts'

export type TCPTunnelCreateOpts = {
	/**
	 * The tunnel ID to communicate with.
	 */
	tunnelId: CreateTunnelRequest['id']
	client: IAttestorClient
}

/**
 * Makes a tunnel communication wrapper for a TCP tunnel.
 *
 * It listens for messages and disconnect events from the server,
 * and appropriately calls the `onMessage` and `onClose` callbacks.
 */
export const makeRpcTcpTunnel: MakeTunnelFn<TCPTunnelCreateOpts> = ({
	tunnelId,
	client,
	onClose,
	onMessage,
}) => {
	let closed = false
	client.addEventListener('tunnel-message', onMessageListener)
	client.addEventListener('tunnel-disconnect-event', onDisconnectListener)
	client.addEventListener('connection-terminated', onConnectionTerminatedListener)

	return {
		async write(message) {
			await client.sendMessage({ tunnelMessage: { tunnelId, message } })
		},
		async close(err) {
			if(closed) {
				return
			}

			// The RPC first, the teardown after. `onErrorRecv` removes the
			// 'tunnel-message' listener, and the server spends the whole of
			// disconnectTunnel handing over the bytes it had already received
			// -- the ones every Witness on the route has signed for. Tearing
			// the listener down first dispatched all of them into nothing.
			try {
				await client.rpc('disconnectTunnel', { id: tunnelId })
			} finally {
				onErrorRecv(err)
			}
		}
	}

	function onMessageListener({ data }: RPCEvent<'tunnel-message'>) {
		if(data.tunnelId !== tunnelId) {
			return
		}

		onMessage?.(data.message)
	}

	function onDisconnectListener({ data }: RPCEvent<'tunnel-disconnect-event'>) {
		if(data.tunnelId !== tunnelId) {
			return
		}

		onErrorRecv(
			data.error?.code
				? AttestorError.fromProto(data.error)
				: undefined
		)
	}

	function onConnectionTerminatedListener({ data }: RPCEvent<'connection-terminated'>) {
		onErrorRecv(data)
	}

	function onErrorRecv(err: Error | undefined) {
		client.logger?.debug({ tunnelId, err }, 'TCP tunnel closed')

		client.removeEventListener('tunnel-message', onMessageListener)
		client.removeEventListener('tunnel-disconnect-event', onDisconnectListener)
		client.removeEventListener('connection-terminated', onConnectionTerminatedListener)
		onClose?.(err)
		onClose = undefined
		closed = true
	}
}