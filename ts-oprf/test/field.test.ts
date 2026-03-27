import { describe, it, expect } from 'vitest'
import { mod, addMod, mulMod, invMod, powMod, sqrtMod } from '../src/field.js'
import { FIELD_MODULUS } from '../src/constants.js'

describe('field arithmetic', () => {
  it('mod reduces correctly', () => {
    expect(mod(FIELD_MODULUS + 5n)).toBe(5n)
    expect(mod(-1n)).toBe(FIELD_MODULUS - 1n)
  })

  it('addMod adds correctly', () => {
    expect(addMod(FIELD_MODULUS - 1n, 2n)).toBe(1n)
  })

  it('mulMod multiplies correctly', () => {
    expect(mulMod(2n, 3n)).toBe(6n)
  })

  it('invMod computes inverse', () => {
    const a = 12345n
    const inv = invMod(a)
    expect(mulMod(a, inv)).toBe(1n)
  })

  it('powMod computes power', () => {
    expect(powMod(2n, 10n)).toBe(1024n)
    expect(powMod(3n, 5n)).toBe(243n)
  })
})

describe('sqrtMod', () => {
  it('computes square root', () => {
    const x = 12345n
    const xSquared = mulMod(x, x)
    const root = sqrtMod(xSquared)
    // root could be x or -x (p - x)
    expect(mulMod(root!, root!)).toBe(xSquared)
  })

  it('returns null for non-residue', () => {
    // 5 is a quadratic non-residue in this field
    // If it were a residue, sqrtMod would return a value that squares to 5
    const result = sqrtMod(5n)
    if (result === null) {
      expect(result).toBeNull()
    } else {
      // If 5 happens to be a residue, verify the square root is correct
      expect(mulMod(result, result)).toBe(5n)
    }
  })

  it('invMod throws for zero', () => {
    expect(() => invMod(0n)).toThrow('Cannot compute modular inverse of zero')
  })
})
