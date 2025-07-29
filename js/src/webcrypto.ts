// if bundling in the browser, this should be replaced with an empty
// import, so we'll use the `crypto` global from the browser
import { webcrypto as _webcrypto } from 'crypto'

let webcrypto: Crypto
if(typeof _webcrypto === 'undefined') {
	webcrypto = window.crypto
} else if(typeof self !== 'undefined' && self.crypto) {
	webcrypto = self.crypto
} else {
	// @ts-expect-error
	webcrypto = _webcrypto
}

export { webcrypto }