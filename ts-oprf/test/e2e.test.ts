import { describe, it, expect } from 'vitest'
import { generateOPRFRequest, finalizeOPRF } from '../src'
import { scalarMul } from '../src/curve.js'
import { unmarshalPoint, marshalPoint } from '../src'
import { hashPoints } from '../src/dleq.js'
import { BASE_POINT, CURVE_ORDER } from '../src'
import { mod } from '../src/field.js'
import type { OPRFResponse } from '../src'

// Simulate full OPRF flow with mock server (without cofactor clearing - matches attestor)
describe('E2E OPRF flow', () => {
  it('completes full OPRF flow', () => {
    // Server setup
    const serverSk = 98765432123456789n
    const serverPk = scalarMul(BASE_POINT, serverSk)

    // Client: generate request
    const secret = new TextEncoder().encode('my secret data')
    const domain = 'my-app-v1'
    const request = generateOPRFRequest(secret, domain)

    // Server: evaluate
    const masked = unmarshalPoint(request.maskedData)
    const evaluated = scalarMul(masked, serverSk)

    // Server: generate DLEQ proof (no cofactor clearing)
    // Hash order: base, xG, vG, vH, H, xH
    const v = 11111111111n
    const vG = scalarMul(BASE_POINT, v)
    const vH = scalarMul(masked, v)
    const c = hashPoints([BASE_POINT, serverPk, vG, vH, masked, evaluated])
    const r = mod(v - c * serverSk, CURVE_ORDER)

    // Server: build response
    const response: OPRFResponse = {
      publicKeyShare: marshalPoint(serverPk),
      evaluated: marshalPoint(evaluated),
      c: bigintToBytes(c),
      r: bigintToBytes(r),
    }

    // Client: finalize
    const output = finalizeOPRF(response.publicKeyShare, request, response)

    // Verify determinism
    const output2 = finalizeOPRF(response.publicKeyShare, request, response)
    expect(output.nullifier).toBe(output2.nullifier)

    // Different secret should produce different nullifier
    const request2 = generateOPRFRequest(
      new TextEncoder().encode('different secret'),
      domain
    )
    const masked2 = unmarshalPoint(request2.maskedData)
    const evaluated2 = scalarMul(masked2, serverSk)
    const vH2 = scalarMul(masked2, v)
    const c2 = hashPoints([BASE_POINT, serverPk, vG, vH2, masked2, evaluated2])
    const r2 = mod(v - c2 * serverSk, CURVE_ORDER)
    const response2: OPRFResponse = {
      publicKeyShare: marshalPoint(serverPk),
      evaluated: marshalPoint(evaluated2),
      c: bigintToBytes(c2),
      r: bigintToBytes(r2),
    }
    const output3 = finalizeOPRF(response2.publicKeyShare, request2, response2)
    expect(output3.nullifier).not.toBe(output.nullifier)
  })

  it('rejects tampered response', () => {
    const serverSk = 98765432123456789n
    const secret = new TextEncoder().encode('test')
    const request = generateOPRFRequest(secret, 'domain')
    const masked = unmarshalPoint(request.maskedData)
    const evaluated = scalarMul(masked, serverSk)

    // Tampered response with wrong c/r
    const response: OPRFResponse = {
      publicKeyShare: marshalPoint(scalarMul(BASE_POINT, serverSk)),
      evaluated: marshalPoint(evaluated),
      c: new Uint8Array([1, 2, 3]),
      r: new Uint8Array([4, 5, 6]),
    }

    expect(() => finalizeOPRF(response.publicKeyShare, request, response))
      .toThrow('DLEQ proof verification failed')
  })
})

function bigintToBytes(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array([0])
  const hex = n.toString(16)
  const paddedHex = hex.length % 2 === 0 ? hex : '0' + hex
  const bytes = new Uint8Array(paddedHex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(paddedHex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}
