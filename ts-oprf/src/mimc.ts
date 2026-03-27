import { keccak_256 } from '@noble/hashes/sha3'
import { FIELD_MODULUS, MIMC_ROUNDS, MIMC_SEED } from './constants.js'
import { addMod, powMod } from './field.js'

let cachedConstants: bigint[] | null = null

export function generateMimcConstants(): bigint[] {
  if (cachedConstants) return cachedConstants

  const constants: bigint[] = []

  // Pre-hash the seed first (matches gnark-crypto behavior)
  let rnd = keccak_256(new TextEncoder().encode(MIMC_SEED))
  // Hash the pre-hash result to start the chain
  rnd = keccak_256(rnd)

  for (let i = 0; i < MIMC_ROUNDS; i++) {
    // Convert hash to bigint and reduce mod field
    let value = 0n
    for (let j = 0; j < 32; j++) {
      value = (value << 8n) | BigInt(rnd[j])
    }
    constants.push(value % FIELD_MODULUS)

    // Hash again for next constant
    rnd = keccak_256(rnd)
  }

  cachedConstants = constants
  return constants
}

function mimcEncrypt(m: bigint, h: bigint, constants: bigint[]): bigint {
  for (let i = 0; i < MIMC_ROUNDS; i++) {
    const tmp = addMod(addMod(m, h), constants[i])
    m = powMod(tmp, 5n) // x^5
  }
  return addMod(m, h)
}

export function mimcHash(inputs: bigint[]): bigint {
  const constants = generateMimcConstants()
  let h = 0n

  for (const m of inputs) {
    const encrypted = mimcEncrypt(m, h, constants)
    // Miyaguchi-Preneel: h = encrypt(m, h) + h + m
    h = addMod(addMod(encrypted, h), m)
  }

  return h
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  if (bytes.length === 0) return 0n
  let result = 0n
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i])
  }
  return result
}

export function hashToScalar(inputs: Uint8Array[]): bigint {
  const bigIntInputs: bigint[] = []
  for (const input of inputs) {
    // Empty bytes become [0] to match Go implementation
    if (input.length === 0) {
      bigIntInputs.push(0n)
    } else {
      bigIntInputs.push(bytesToBigInt(input))
    }
  }
  return mimcHash(bigIntInputs)
}
