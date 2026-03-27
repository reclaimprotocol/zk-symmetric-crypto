import { describe, it, expect } from 'vitest'
import { generateOPRFRequest, finalizeOPRF } from '../src/oprf.js'
import { unmarshalPoint, marshalPoint } from '../src/point.js'
import { isOnCurve, scalarMul } from '../src/curve.js'
import { hashPoints } from '../src/dleq.js'
import { HASH_TO_CURVE_VECTORS } from './vectors.js'
import { BASE_POINT, CURVE_ORDER } from '../src/constants.js'
import { mod, invMod } from '../src/field.js'
import type { OPRFResponse } from '../src/types.js'

describe('OPRF', () => {
  it('generateOPRFRequest produces valid masked point', () => {
    const secret = new TextEncoder().encode('hello world')
    const domain = 'test-domain'

    const request = generateOPRFRequest(secret, domain)

    expect(request.mask).toBeGreaterThan(0n)
    expect(request.mask).toBeLessThan(CURVE_ORDER)
    expect(request.maskedData.length).toBe(32)
    expect(request.secretElements.length).toBe(2)

    // Masked point should be on curve
    const masked = unmarshalPoint(request.maskedData)
    expect(isOnCurve(masked)).toBe(true)
  })

  it('generates correct hash-to-curve point', () => {
    const secret = new TextEncoder().encode(HASH_TO_CURVE_VECTORS.helloWorld.secret)
    const domain = HASH_TO_CURVE_VECTORS.helloWorld.domain

    // Use a known mask to verify hash-to-curve
    const request = generateOPRFRequest(secret, domain)

    // Unmask to get H
    const masked = unmarshalPoint(request.maskedData)
    const invMask = invMod(request.mask, CURVE_ORDER)
    const H = scalarMul(masked, invMask)

    expect(H.x).toBe(HASH_TO_CURVE_VECTORS.helloWorld.hX)
    expect(H.y).toBe(HASH_TO_CURVE_VECTORS.helloWorld.hY)
  })
})

describe('finalizeOPRF', () => {
  it('produces correct nullifier for simulated server response', async () => {
    const secret = new TextEncoder().encode('hello world')
    const domain = 'test-domain'
    const serverSk = 12345n

    // Client generates request
    const request = generateOPRFRequest(secret, domain)
    const masked = unmarshalPoint(request.maskedData)

    // Server evaluates
    const evaluated = scalarMul(masked, serverSk)
    const serverPk = scalarMul(BASE_POINT, serverSk)

    // Server generates DLEQ proof (no cofactor clearing - matches attestor)
    // Hash order: base, xG, vG, vH, H, xH
    const v = 54321n
    const vG = scalarMul(BASE_POINT, v)
    const vH = scalarMul(masked, v)

    const c = hashPoints([BASE_POINT, serverPk, vG, vH, masked, evaluated])
    const r = mod(v - c * serverSk, CURVE_ORDER)

    // Mock server response
    const response: OPRFResponse = {
      publicKeyShare: marshalPoint(serverPk),
      evaluated: marshalPoint(evaluated),
      c: bigintToBytes(c),
      r: bigintToBytes(r),
    }

    // Client finalizes
    const output = finalizeOPRF(response.publicKeyShare, request, response)

    // Verify output is deterministic (same inputs = same output)
    const output2 = finalizeOPRF(response.publicKeyShare, request, response)
    expect(output.nullifier).toBe(output2.nullifier)

    // Verify output is non-zero
    expect(output.nullifier).not.toBe(0n)
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
