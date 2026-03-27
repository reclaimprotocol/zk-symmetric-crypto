import { describe, it, expect } from 'vitest'
import { marshalPoint, unmarshalPoint } from '../src/point.js'
import { scalarMul } from '../src/curve.js'
import { BASE_POINT } from '../src/constants.js'
import { POINT_VECTORS } from './vectors.js'

describe('point serialization', () => {
  it('marshals point correctly', () => {
    const point = scalarMul(BASE_POINT, POINT_VECTORS.scalarMult.scalar)
    const marshaled = marshalPoint(point)
    expect(bytesToHex(marshaled)).toBe(POINT_VECTORS.scalarMult.marshaled)
  })

  it('unmarshals point correctly', () => {
    const bytes = hexToBytes(POINT_VECTORS.scalarMult.marshaled)
    const point = unmarshalPoint(bytes)
    expect(point.x).toBe(POINT_VECTORS.scalarMult.x)
    expect(point.y).toBe(POINT_VECTORS.scalarMult.y)
  })

  it('roundtrip marshal/unmarshal', () => {
    const original = scalarMul(BASE_POINT, 99999n)
    const marshaled = marshalPoint(original)
    const recovered = unmarshalPoint(marshaled)
    expect(recovered.x).toBe(original.x)
    expect(recovered.y).toBe(original.y)
  })
})

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}
