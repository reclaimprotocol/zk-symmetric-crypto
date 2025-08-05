import { setCryptoImplementation } from '@reclaimprotocol/tls'
import { webcryptoCrypto } from '@reclaimprotocol/tls/webcrypto'

setCryptoImplementation(webcryptoCrypto)