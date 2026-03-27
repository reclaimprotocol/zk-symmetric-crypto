/**
 * Test vectors for DLEQ verification (without cofactor clearing - matches attestor's library)
 *
 * These tests verify that the TypeScript implementation correctly:
 * 1. Unmarshals points in compressed format
 * 2. Computes scalar multiplications
 * 3. Verifies DLEQ proofs using the hash order: base, xG, vG, vH, H, xH
 */
import { describe, it, expect } from 'vitest'
import { unmarshalPoint, marshalPoint } from '../src/point.js'
import { BASE_POINT, CURVE_ORDER } from '../src/constants.js'
import { scalarMul, pointAdd } from '../src/curve.js'
import { hashPoints, verifyDLEQ } from '../src/dleq.js'
import { mod } from '../src/field.js'

describe('Point Marshaling', () => {
  it('should marshal and unmarshal points correctly', () => {
    // Test with a known point (3 * G)
    const point = scalarMul(BASE_POINT, 3n)
    const marshaled = marshalPoint(point)
    const unmarshaled = unmarshalPoint(marshaled)

    expect(unmarshaled.x).toBe(point.x)
    expect(unmarshaled.y).toBe(point.y)
  })

  it('should marshal points in compressed format (32 bytes)', () => {
    const point = scalarMul(BASE_POINT, 12345n)
    const marshaled = marshalPoint(point)
    expect(marshaled.length).toBe(32)
  })
})

describe('DLEQ Verification (no cofactor clearing)', () => {
  it('should verify a self-generated DLEQ proof', () => {
    // Use a known secret key
    const sk = 12345678901234567890n

    // Create a masked point H (use 7*G for simplicity)
    const H = scalarMul(BASE_POINT, 7n)

    // Compute xG = sk * G (public key)
    const xG = scalarMul(BASE_POINT, sk)

    // Compute xH = sk * H (evaluated point)
    const xH = scalarMul(H, sk)

    // Use a fixed v for reproducibility
    const v = 98765432109876543210n

    // Compute vG = v * G
    const vG = scalarMul(BASE_POINT, v)

    // Compute vH = v * H
    const vH = scalarMul(H, v)

    // Compute challenge c = Hash(base, xG, vG, vH, H, xH)
    const c = hashPoints([BASE_POINT, xG, vG, vH, H, xH])

    // Compute r = v - c * sk mod order
    const r = mod(v - c * sk, CURVE_ORDER)

    // Verify the proof
    const result = verifyDLEQ(c, r, xG, xH, H)
    expect(result).toBe(true)
  })

  it('should reconstruct vG and vH correctly from r and c', () => {
    const sk = 55555555555555555555n
    const H = scalarMul(BASE_POINT, 11n)
    const xG = scalarMul(BASE_POINT, sk)
    const xH = scalarMul(H, sk)
    const v = 77777777777777777777n

    // Original vG and vH
    const vG = scalarMul(BASE_POINT, v)
    const vH = scalarMul(H, v)

    // Compute c and r
    const c = hashPoints([BASE_POINT, xG, vG, vH, H, xH])
    const r = mod(v - c * sk, CURVE_ORDER)

    // Reconstruct vG' = r*G + c*xG
    const rG = scalarMul(BASE_POINT, mod(r, CURVE_ORDER))
    const cXG = scalarMul(xG, mod(c, CURVE_ORDER))
    const vGReconstructed = pointAdd(rG, cXG)

    // Reconstruct vH' = r*H + c*xH
    const rH = scalarMul(H, mod(r, CURVE_ORDER))
    const cXH = scalarMul(xH, mod(c, CURVE_ORDER))
    const vHReconstructed = pointAdd(rH, cXH)

    // Should match original
    expect(vGReconstructed.x).toBe(vG.x)
    expect(vGReconstructed.y).toBe(vG.y)
    expect(vHReconstructed.x).toBe(vH.x)
    expect(vHReconstructed.y).toBe(vH.y)
  })

  it('should reject invalid DLEQ proofs', () => {
    const sk = 11111111111111111111n
    const H = scalarMul(BASE_POINT, 5n)
    const xG = scalarMul(BASE_POINT, sk)
    const xH = scalarMul(H, sk)
    const v = 22222222222222222222n

    const vG = scalarMul(BASE_POINT, v)
    const vH = scalarMul(H, v)

    const c = hashPoints([BASE_POINT, xG, vG, vH, H, xH])
    const r = mod(v - c * sk, CURVE_ORDER)

    // Tamper with r
    const badR = r + 1n

    const result = verifyDLEQ(c, badR, xG, xH, H)
    expect(result).toBe(false)
  })
})
