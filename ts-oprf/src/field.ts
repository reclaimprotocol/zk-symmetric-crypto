import { FIELD_MODULUS } from './constants.js'

export function mod(a: bigint, p: bigint = FIELD_MODULUS): bigint {
  const result = a % p
  return result >= 0n ? result : result + p
}

export function addMod(a: bigint, b: bigint, p: bigint = FIELD_MODULUS): bigint {
  return mod(a + b, p)
}

export function subMod(a: bigint, b: bigint, p: bigint = FIELD_MODULUS): bigint {
  return mod(a - b, p)
}

export function mulMod(a: bigint, b: bigint, p: bigint = FIELD_MODULUS): bigint {
  return mod(a * b, p)
}

export function powMod(base: bigint, exp: bigint, p: bigint = FIELD_MODULUS): bigint {
  let result = 1n
  base = mod(base, p)
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = mulMod(result, base, p)
    }
    exp = exp / 2n
    base = mulMod(base, base, p)
  }
  return result
}

export function invMod(a: bigint, p: bigint = FIELD_MODULUS): bigint {
  a = mod(a, p)
  if (a === 0n) {
    throw new Error('Cannot compute modular inverse of zero')
  }
  // Fermat's little theorem: a^(p-2) = a^(-1) mod p
  return powMod(a, p - 2n, p)
}

export function sqrtMod(n: bigint, p: bigint = FIELD_MODULUS): bigint | null {
  n = mod(n, p)
  if (n === 0n) return 0n

  // Check if n is a quadratic residue using Euler's criterion
  if (powMod(n, (p - 1n) / 2n, p) !== 1n) {
    return null
  }

  // Tonelli-Shanks algorithm
  // Factor out powers of 2 from p - 1
  let q = p - 1n
  let s = 0n
  while (q % 2n === 0n) {
    q = q / 2n
    s++
  }

  // Find a quadratic non-residue
  let z = 2n
  while (powMod(z, (p - 1n) / 2n, p) !== p - 1n) {
    z++
  }

  let m = s
  let c = powMod(z, q, p)
  let t = powMod(n, q, p)
  let r = powMod(n, (q + 1n) / 2n, p)

  while (true) {
    if (t === 0n) return 0n
    if (t === 1n) return r

    // Find the least i such that t^(2^i) = 1
    let i = 1n
    let temp = mulMod(t, t, p)
    while (temp !== 1n) {
      temp = mulMod(temp, temp, p)
      i++
    }

    // Update values
    const b = powMod(c, powMod(2n, m - i - 1n, p - 1n), p)
    m = i
    c = mulMod(b, b, p)
    t = mulMod(t, c, p)
    r = mulMod(r, b, p)
  }
}
