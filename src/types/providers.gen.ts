/* eslint-disable */
/* Generated file. Do not edit */

type BinaryData = Uint8Array | string

export interface HttpProviderParameters {
  /**
   * which URL does the request have to be made to Has to be a valid https URL for eg. https://amazon.in/orders?q=abcd
   */
  url: string;
  method: "GET" | "POST" | "PUT" | "PATCH";
  /**
   * Specify the geographical location from where to proxy the request. 2-letter ISO country code or parameter (public or secret)
   */
  geoLocation?: string;
  /**
   * Specify the unique session id for allowing use of same proxy ip across multiple requests. Can be a smallcase alphanumeric string of length 8-14 characters. eg. "mystring12345", "something1234".
   */
  proxySessionId?: string;
  /**
   * Any additional headers to be sent with the request Note: these will be revealed to the attestor & won't be redacted from the transcript. To add hidden headers, use 'secretParams.headers' instead
   */
  headers?: {
    [k: string]: string;
  };
  /**
   * Body of the HTTP request
   */
  body?: BinaryData;
  /**
   * If the API doesn't perform well with the "key-update" method of redaction, you can switch to "zk" mode by setting this to "zk"
   */
  writeRedactionMode?: "zk" | "key-update";
  /**
   * Apply TLS configuration when creating the tunnel to the attestor.
   */
  additionalClientOptions?: {
    /**
     * @minItems 1
     */
    supportedProtocolVersions?: ("TLS1_2" | "TLS1_3")[];
  };
  /**
   * The attestor will use this list to check that the redacted response does indeed match all the provided strings/regexes
   *
   * @minItems 1
   */
  responseMatches: {
    /**
     * "regex": the response must match the regex "contains": the response must contain the provided
     *  string exactly
     */
    value: string;
    /**
     * The string/regex to match against
     */
    type: "regex" | "contains";
    /**
     * Inverses the matching logic. Fail when match is found and proceed otherwise
     */
    invert?: boolean;
  }[];
  /**
   * which portions to select from a response. These are selected in order, xpath => jsonPath => regex * These redactions are done client side and only the selected portions are sent to the attestor. The attestor will only be able to see the selected portions alongside the first line of the HTTP response (i.e. "HTTP/1.1 200 OK") * To disable any redactions, pass an empty array
   */
  responseRedactions?: {
    /**
     * expect an HTML response, and to contain a certain xpath for eg. "/html/body/div.a1/div.a2/span.a5"
     */
    xPath?: string;
    /**
     * expect a JSON response, retrieve the item at this path using dot notation for e.g. 'email.addresses.0'
     */
    jsonPath?: string;
    /**
     * select a regex match from the response
     */
    regex?: string;
    /**
     * If provided, the value inside will be hashed instead of being redacted. Useful for cases where the data inside is an identifiying piece of information that you don't want to reveal to the attestor, eg. an email address.
     * If the hash function produces more bytes than the original value, the hash will be truncated.
     * Eg. if hash is enabled, the original value is "hello", and hashed is "a1b2c", then the attestor will only see "a1b2c".
     * Note: if a regex with named groups is provided, only the named groups will be hashed.
     */
    hash?: "oprf" | "oprf-mpc" | "oprf-raw";
  }[];
  /**
   * A map of parameter values which are user in form of {{param}} in URL, responseMatches, responseRedactions, body, geolocation. Those in URL, responseMatches & geo will be put into context and signed This value will NOT be included in provider hash
   */
  paramValues?: {
    [k: string]: string;
  };
}

export const HttpProviderParametersJson = {"title":"HttpProviderParameters","type":"object","required":["url","method","responseMatches"],"properties":{"url":{"type":"string","format":"url","description":"which URL does the request have to be made to Has to be a valid https URL for eg. https://amazon.in/orders?q=abcd"},"method":{"type":"string","enum":["GET","POST","PUT","PATCH"]},"geoLocation":{"type":"string","nullable":true,"description":"Specify the geographical location from where to proxy the request. 2-letter ISO country code or parameter (public or secret)"},"proxySessionId":{"type":"string","nullable":true,"description":"Specify the unique session id for allowing use of same proxy ip across multiple requests. Can be a smallcase alphanumeric string of length 8-14 characters. eg. \"mystring12345\", \"something1234\"."},"headers":{"type":"object","description":"Any additional headers to be sent with the request Note: these will be revealed to the attestor & won't be redacted from the transcript. To add hidden headers, use 'secretParams.headers' instead","additionalProperties":{"type":"string"}},"body":{"description":"Body of the HTTP request","oneOf":[{"type":"string","format":"binary"},{"type":"string"}]},"writeRedactionMode":{"type":"string","description":"If the API doesn't perform well with the \"key-update\" method of redaction, you can switch to \"zk\" mode by setting this to \"zk\"","enum":["zk","key-update"]},"additionalClientOptions":{"type":"object","description":"Apply TLS configuration when creating the tunnel to the attestor.","nullable":true,"properties":{"supportedProtocolVersions":{"type":"array","minItems":1,"uniqueItems":true,"items":{"type":"string","enum":["TLS1_2","TLS1_3"]}}}},"responseMatches":{"type":"array","minItems":1,"uniqueItems":true,"description":"The attestor will use this list to check that the redacted response does indeed match all the provided strings/regexes","items":{"type":"object","required":["value","type"],"properties":{"value":{"type":"string","description":"\"regex\": the response must match the regex \"contains\": the response must contain the provided\n string exactly"},"type":{"type":"string","description":"The string/regex to match against","enum":["regex","contains"]},"invert":{"type":"boolean","description":"Inverses the matching logic. Fail when match is found and proceed otherwise"}},"additionalProperties":false}},"responseRedactions":{"type":"array","uniqueItems":true,"description":"which portions to select from a response. These are selected in order, xpath => jsonPath => regex * These redactions are done client side and only the selected portions are sent to the attestor. The attestor will only be able to see the selected portions alongside the first line of the HTTP response (i.e. \"HTTP/1.1 200 OK\") * To disable any redactions, pass an empty array","items":{"type":"object","properties":{"xPath":{"type":"string","nullable":true,"description":"expect an HTML response, and to contain a certain xpath for eg. \"/html/body/div.a1/div.a2/span.a5\""},"jsonPath":{"type":"string","nullable":true,"description":"expect a JSON response, retrieve the item at this path using dot notation for e.g. 'email.addresses.0'"},"regex":{"type":"string","nullable":true,"description":"select a regex match from the response"},"hash":{"type":"string","description":"If provided, the value inside will be hashed instead of being redacted. Useful for cases where the data inside is an identifiying piece of information that you don't want to reveal to the attestor, eg. an email address.\nIf the hash function produces more bytes than the original value, the hash will be truncated.\nEg. if hash is enabled, the original value is \"hello\", and hashed is \"a1b2c\", then the attestor will only see \"a1b2c\".\nNote: if a regex with named groups is provided, only the named groups will be hashed.","enum":["oprf","oprf-mpc","oprf-raw"]}},"additionalProperties":false}},"paramValues":{"type":"object","description":"A map of parameter values which are user in form of {{param}} in URL, responseMatches, responseRedactions, body, geolocation. Those in URL, responseMatches & geo will be put into context and signed This value will NOT be included in provider hash","additionalProperties":{"type":"string"}}},"additionalProperties":false}
/**
 * Secret parameters to be used with HTTP provider. None of the values in this object will be shown to the attestor
 */
export interface HttpProviderSecretParameters {
  /**
   * cookie string for authorisation.
   */
  cookieStr?: string;
  /**
   * authorisation header value
   */
  authorisationHeader?: string;
  /**
   * Headers that need to be hidden from the attestor
   */
  headers?: {
    [k: string]: string;
  };
  /**
   * A map of parameter values which are user in form of {{param}} in body these parameters will NOT be shown to attestor and extracted
   */
  paramValues?: {
    [k: string]: string;
  };
}

export const HttpProviderSecretParametersJson = {"title":"HttpProviderSecretParameters","type":"object","description":"Secret parameters to be used with HTTP provider. None of the values in this object will be shown to the attestor","properties":{"cookieStr":{"type":"string","description":"cookie string for authorisation."},"authorisationHeader":{"type":"string","description":"authorisation header value"},"headers":{"type":"object","description":"Headers that need to be hidden from the attestor","additionalProperties":{"type":"string"}},"paramValues":{"type":"object","description":"A map of parameter values which are user in form of {{param}} in body these parameters will NOT be shown to attestor and extracted","additionalProperties":{"type":"string"}}},"additionalProperties":false}
export interface TokenswimWindowParameters {
	url: string
	method: string
	headers?: { [k: string]: string }
	body?: string
	/** hex digest of the client direction's ciphertext, the seed for its windows */
	clientDigest: string
	/** hex digest of the server direction's ciphertext */
	serverDigest: string
	windowCount: number
	/**
	 * How many bytes of application data each direction carried. Named rather
	 * than only derived because the claim path arrives at it twice — once from
	 * the undecrypted transcript and once from the decrypted receipt — and the
	 * proven ranges below mean the same bytes at both ends only when the two
	 * agree.
	 */
	clientLength: number
	serverLength: number
	/**
	 * The [from, to) ranges of each direction's application data that a ZK proof
	 * covers, in the same coordinates as the challenge windows. Sorted, with
	 * touching ranges fused. Redaction is marked with a byte that is also legal
	 * data, so this is what says a challenged byte was answered with a proof at
	 * all rather than with the sentinel.
	 */
	clientProven: [number, number][]
	serverProven: [number, number][]
	/**
	 * Every Witness in the relay path, each with its BLS12-381 public key and
	 * its signature over SHA-256(clientDigest ‖ serverDigest). At least two, all
	 * distinct; the protocol sets no upper bound, so this is a list rather than
	 * a fixed pair of fields.
	 */
	witnesses: {
		publicKey: string
		signature: string
	}[]
	/**
	 * The rest of what each Witness signature covers. A receipt commits to the
	 * route slot, the transcript root, both digests, both application lengths
	 * and the response leaf count under a domain tag -- seven fields, of which
	 * the two digests above are two. Without these five a verifier cannot
	 * rebuild the message that was signed, so it can check nothing.
	 */
	routeSlotId: number
	/** hex, 32 bytes: the Merkle root over the server-direction leaves */
	transcriptRoot: string
	clientApplicationLen: number
	serverApplicationLen: number
	responseLeafCount: number
	/**
	 * [from, to) over the client direction, revealed on top of the challenged
	 * windows because it names the model. Absent when the request named none.
	 */
	modelChunk?: [number, number]
	/**
	 * [from, to) of the `"model": value` pair itself, inside modelChunk. The
	 * chunk is what had to be revealed; this is where to read, because widening
	 * to chunk boundaries can drag a tool schema's own `model` in beside it.
	 */
	modelField?: [number, number]
}

export const TokenswimWindowParametersJson = {
	title: 'TokenswimWindowParameters',
	type: 'object',
	properties: {
		url: { type: 'string' },
		method: { type: 'string' },
		headers: { type: 'object', additionalProperties: { type: 'string' } },
		body: { type: 'string' },
		clientDigest: { type: 'string' },
		serverDigest: { type: 'string' },
		windowCount: { type: 'number' },
		clientLength: { type: 'number' },
		serverLength: { type: 'number' },
		clientProven: {
			type: 'array',
			items: {
				type: 'array', items: { type: 'number' }, minItems: 2, maxItems: 2,
			},
		},
		serverProven: {
			type: 'array',
			items: {
				type: 'array', items: { type: 'number' }, minItems: 2, maxItems: 2,
			},
		},
		witnesses: {
			type: 'array',
			minItems: 2,
			items: {
				type: 'object',
				properties: {
					publicKey: { type: 'string' },
					signature: { type: 'string' },
				},
				required: ['publicKey', 'signature'],
				additionalProperties: false,
			},
		},
		routeSlotId: { type: 'number' },
		transcriptRoot: { type: 'string' },
		clientApplicationLen: { type: 'number' },
		serverApplicationLen: { type: 'number' },
		responseLeafCount: { type: 'number' },
		modelChunk: {
			type: 'array', items: { type: 'number' }, minItems: 2, maxItems: 2,
		},
		modelField: {
			type: 'array', items: { type: 'number' }, minItems: 2, maxItems: 2,
		},
	},
	required: [
		'url', 'method', 'clientDigest', 'serverDigest', 'windowCount', 'witnesses',
		'clientLength', 'serverLength', 'clientProven', 'serverProven',
		'routeSlotId', 'transcriptRoot', 'clientApplicationLen',
		'serverApplicationLen', 'responseLeafCount',
	],
	additionalProperties: false,
}

export const TokenswimWindowSecretParametersJson = {
	title: 'TokenswimWindowSecretParameters',
	type: 'object',
	properties: {},
	additionalProperties: false,
}

export interface ProvidersConfig {
	tokenswimWindow: {
		parameters: TokenswimWindowParameters
		secretParameters: Record<string, never>
	}
	http: {
		parameters: HttpProviderParameters
		secretParameters: HttpProviderSecretParameters
	}
}

export const PROVIDER_SCHEMAS = {
	tokenswimWindow: {
		parameters: TokenswimWindowParametersJson,
		secretParameters: TokenswimWindowSecretParametersJson
	},
	http: {
		parameters: HttpProviderParametersJson,
		secretParameters: HttpProviderSecretParametersJson
	},
}
