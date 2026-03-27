import { describe, it, expect } from 'vitest'
import { generateMimcConstants, mimcHash, hashToScalar } from '../src/mimc.js'
import { MIMC_VECTORS } from './vectors.js'

describe('MiMC', () => {
  it('generates correct first constant', () => {
    const constants = generateMimcConstants()
    expect(constants[0]).toBe(MIMC_VECTORS.firstConstant)
  })

  it('generates 110 constants', () => {
    const constants = generateMimcConstants()
    expect(constants.length).toBe(110)
  })
})

describe('mimcHash', () => {
  it('hashes two inputs correctly', () => {
    const result = mimcHash(MIMC_VECTORS.twoInputs.inputs)
    expect(result).toBe(MIMC_VECTORS.twoInputs.output)
  })

  it('hashes single input correctly', () => {
    const result = mimcHash(MIMC_VECTORS.singleInput.inputs)
    expect(result).toBe(MIMC_VECTORS.singleInput.output)
  })
})

describe('hashToScalar', () => {
  it('handles empty bytes as [0]', () => {
    const result1 = hashToScalar([new Uint8Array([0])])
    const result2 = hashToScalar([new Uint8Array(0)])
    expect(result1).toBe(result2)
  })

  it('matches Go implementation for bytes input', () => {
    // BigInt(12345).bytes() = [0x30, 0x39]
    // BigInt(67890).bytes() = [0x01, 0x09, 0x32]
    const input1 = new Uint8Array([0x30, 0x39])
    const input2 = new Uint8Array([0x01, 0x09, 0x32])
    const result = hashToScalar([input1, input2])
    expect(result).toBe(MIMC_VECTORS.twoInputs.output)
  })
})
