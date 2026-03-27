import { describe, it, expect } from 'vitest'
import { verifyDLEQ, hashPoints } from '../src/dleq.js'
import { scalarMul } from '../src/curve.js'
import { BASE_POINT, CURVE_ORDER } from '../src/constants.js'
import { mod } from '../src/field.js'

describe('DLEQ', () => {
  it('hashPoints produces consistent output', () => {
    const p1 = scalarMul(BASE_POINT, 123n)
    const p2 = scalarMul(BASE_POINT, 456n)
    const hash1 = hashPoints([p1, p2])
    const hash2 = hashPoints([p1, p2])
    expect(hash1).toBe(hash2)
  })

  it('verifies valid DLEQ proof', () => {
    // Simulate server-side proof generation (without cofactor clearing - matches attestor)
    const sk = 12345n
    const H = scalarMul(BASE_POINT, 9999n) // Some point

    // xG = G * sk, xH = H * sk
    const xG = scalarMul(BASE_POINT, sk)
    const xH = scalarMul(H, sk)

    // Random v for proof
    const v = 54321n
    const vG = scalarMul(BASE_POINT, v)
    const vH = scalarMul(H, v)

    // Challenge: Hash(base, xG, vG, vH, H, xH) - no cofactor clearing
    const c = hashPoints([BASE_POINT, xG, vG, vH, H, xH])

    // Response: r = v - c * sk mod order (not c * 8 * sk)
    const r = mod(v - c * sk, CURVE_ORDER)

    // Verify
    const valid = verifyDLEQ(c, r, xG, xH, H)
    expect(valid).toBe(true)
  })

  it('rejects invalid DLEQ proof', () => {
    const sk = 12345n
    const H = scalarMul(BASE_POINT, 9999n)
    const xG = scalarMul(BASE_POINT, sk)
    const xH = scalarMul(H, sk)

    // Wrong c and r
    const valid = verifyDLEQ(123n, 456n, xG, xH, H)
    expect(valid).toBe(false)
  })
})
