import { FIELD_MODULUS, CURVE_D } from './constants.js'
import { mod, mulMod, addMod, invMod, sqrtMod } from './field.js'
import { isOnCurve } from './curve.js'
import type { Point } from './types.js'

const HALF_FIELD = FIELD_MODULUS / 2n

export function marshalPoint(p: Point): Uint8Array {
  const bytes = new Uint8Array(32)

  // Y coordinate in little-endian
  let y = p.y
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(y & 0xffn)
    y = y >> 8n
  }

  // Set sign bit if X > Field/2
  if (p.x > HALF_FIELD) {
    bytes[31] |= 0x80
  }

  return bytes
}

export function unmarshalPoint(bytes: Uint8Array): Point {
  if (bytes.length !== 32) {
    throw new Error('Invalid point: expected 32 bytes')
  }

  // Extract sign bit from byte[31]
  const signBit = (bytes[31] & 0x80) !== 0

  // Read Y from little-endian bytes (clear sign bit first)
  const yBytes = new Uint8Array(bytes)
  yBytes[31] &= 0x7f

  let y = 0n
  for (let i = 31; i >= 0; i--) {
    y = (y << 8n) | BigInt(yBytes[i])
  }

  // Compute x² = (y² - 1) / (1 + d·y²)
  const y2 = mulMod(y, y)
  const numerator = mod(y2 - 1n)
  const denominator = addMod(1n, mulMod(CURVE_D, y2))
  const x2 = mulMod(numerator, invMod(denominator))

  // Compute x = sqrt(x²)
  const x = sqrtMod(x2)
  if (x === null) {
    throw new Error('Invalid point: no square root exists')
  }

  // Adjust sign based on sign bit
  let finalX = x
  if (signBit && x <= HALF_FIELD) {
    finalX = mod(-x)
  } else if (!signBit && x > HALF_FIELD) {
    finalX = mod(-x)
  }

  const point = { x: finalX, y }

  if (!isOnCurve(point)) {
    throw new Error('Invalid point: not on curve')
  }

  return point
}
