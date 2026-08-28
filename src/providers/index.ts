import http from '#src/providers/http/index.ts'
import tokenswimWindow, { PROVIDER_NAME as TOKENSWIM_WINDOW } from '#src/providers/tokenswim-window/index.ts'
import type { Provider, ProviderName } from '#src/types/index.ts'

export {
	extractHTMLElement,
	extractHTMLElementIndex,
	extractHTMLElements,
	extractHTMLElementsIndexes,
	extractJSONValueIndex,
	extractJSONValueIndexes,
} from '#src/providers/http/utils.ts'

export const providers: {
	[T in ProviderName]: Provider<T>
} = {
	http,
	[TOKENSWIM_WINDOW]: tokenswimWindow,
}
