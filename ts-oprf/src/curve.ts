import { CURVE_A, CURVE_D, CURVE_ORDER } from './constants.js'
import { mod, addMod, subMod, mulMod, invMod } from './field.js'
import type { Point } from './types.js'

// Identity point on twisted Edwards curve (0, 1)
export const IDENTITY: Point = { x: 0n, y: 1n }

export function isOnCurve(p: Point): boolean {
  // Twisted Edwards: ax² + y² = 1 + dx²y²
  const x2 = mulMod(p.x, p.x)
  const y2 = mulMod(p.y, p.y)
  const left = addMod(mulMod(CURVE_A, x2), y2)
  const right = addMod(1n, mulMod(CURVE_D, mulMod(x2, y2)))
  return left === right
}

export function pointAdd(p1: Point, p2: Point): Point {
  // Twisted Edwards addition formula:
  // x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
  // y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
  const x1y2 = mulMod(p1.x, p2.y)
  const y1x2 = mulMod(p1.y, p2.x)
  const x1x2 = mulMod(p1.x, p2.x)
  const y1y2 = mulMod(p1.y, p2.y)
  const dx1x2y1y2 = mulMod(CURVE_D, mulMod(x1x2, y1y2))

  const x3Num = addMod(x1y2, y1x2)
  const x3Den = addMod(1n, dx1x2y1y2)
  const x3 = mulMod(x3Num, invMod(x3Den))

  const y3Num = subMod(y1y2, mulMod(CURVE_A, x1x2))
  const y3Den = subMod(1n, dx1x2y1y2)
  const y3 = mulMod(y3Num, invMod(y3Den))

  return { x: x3, y: y3 }
}

export function scalarMul(p: Point, k: bigint): Point {
  k = mod(k, CURVE_ORDER)
  let result = IDENTITY
  let temp = p

  while (k > 0n) {
    if (k % 2n === 1n) {
      result = pointAdd(result, temp)
    }
    temp = pointAdd(temp, temp)
    k = k / 2n
  }

  return result
}

export function isIdentity(p: Point): boolean {
  return p.x === 0n && p.y === 1n
}
