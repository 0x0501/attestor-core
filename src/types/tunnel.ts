import type { CreateTunnelRequest } from '#src/proto/api.ts'

export type MakeTunnelBaseOpts<O> = O & {
	onClose?(err?: Error): void
	onMessage?(data: Uint8Array): void
}

export type Tunnel<E> = E & {
	write(data: Uint8Array): void | Promise<void>
	close(err?: Error): void | Promise<void>
}

export type MakeTunnelFn<O, E = {}> = (opts: MakeTunnelBaseOpts<O>) => (
	Tunnel<E> | Promise<Tunnel<E>>
)

export type Transcript<T> = {
	sender: 'client' | 'server'
	message: T
}[]

export type TCPSocketProperties = {
	/**
	 * How many bytes have crossed the tunnel, both directions. A count rather
	 * than the messages: the server-side recording bound nothing (ADR 0036,
	 * ADR 0040) and cost a whole transcript per live session.
	 */
	transcriptBytes(): number
	createRequest: Pick<CreateTunnelRequest, 'host' | 'port' | 'geoLocation' | 'proxySessionId'>
}