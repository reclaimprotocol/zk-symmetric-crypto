import { describe, it, expect } from 'vitest'
import { pointAdd, scalarMul, isOnCurve, IDENTITY } from '../src/curve.js'
import { BASE_POINT } from '../src/constants.js'
import { POINT_VECTORS } from './vectors.js'

describe('BabyJubJub curve', () => {
  it('base point is on curve', () => {
    expect(isOnCurve(BASE_POINT)).toBe(true)
  })

  it('identity is on curve', () => {
    expect(isOnCurve(IDENTITY)).toBe(true)
  })

  it('scalar multiplication matches Go', () => {
    const result = scalarMul(BASE_POINT, POINT_VECTORS.scalarMult.scalar)
    expect(result.x).toBe(POINT_VECTORS.scalarMult.x)
    expect(result.y).toBe(POINT_VECTORS.scalarMult.y)
  })

  it('identity + P = P', () => {
    const result = pointAdd(IDENTITY, BASE_POINT)
    expect(result.x).toBe(BASE_POINT.x)
    expect(result.y).toBe(BASE_POINT.y)
  })

  it('P + P = 2P', () => {
    const twoP = scalarMul(BASE_POINT, 2n)
    const sumP = pointAdd(BASE_POINT, BASE_POINT)
    expect(sumP.x).toBe(twoP.x)
    expect(sumP.y).toBe(twoP.y)
  })
})
