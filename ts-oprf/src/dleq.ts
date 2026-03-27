import { BASE_POINT, CURVE_ORDER } from './constants.js'
import { scalarMul, pointAdd } from './curve.js'
import { hashToScalar } from './mimc.js'
import { mod } from './field.js'
import type { Point } from './types.js'

function bigintToBytes(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array([0])
  const hex = n.toString(16).padStart(64, '0')
  const bytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

export function hashPoints(points: Point[]): bigint {
  const inputs: Uint8Array[] = []
  for (const p of points) {
    inputs.push(bigintToBytes(p.x))
    inputs.push(bigintToBytes(p.y))
  }
  return hashToScalar(inputs)
}

/**
 * Verify DLEQ proof (without cofactor clearing - matches attestor's current library)
 * Hash order: base, xG, vG, vH, H, xH
 */
export function verifyDLEQ(
  c: bigint,
  r: bigint,
  xG: Point, // serverPublicKey
  xH: Point, // evaluated point
  H: Point   // masked point
): boolean {
  // Reconstruct vG = r*G + c*xG
  const rG = scalarMul(BASE_POINT, mod(r, CURVE_ORDER))
  const cXG = scalarMul(xG, mod(c, CURVE_ORDER))
  const vG = pointAdd(rG, cXG)

  // Reconstruct vH = r*H + c*xH
  const rH = scalarMul(H, mod(r, CURVE_ORDER))
  const cXH = scalarMul(xH, mod(c, CURVE_ORDER))
  const vH = pointAdd(rH, cXH)

  // Verify challenge: Hash(base, xG, vG, vH, H, xH)
  const challenge = hashPoints([BASE_POINT, xG, vG, vH, H, xH])

  return challenge === c
}
