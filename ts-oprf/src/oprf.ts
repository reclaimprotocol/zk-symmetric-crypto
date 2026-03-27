import { BASE_POINT, CURVE_ORDER, BYTES_PER_ELEMENT } from './constants.js'
import { scalarMul } from './curve.js'
import { marshalPoint, unmarshalPoint } from './point.js'
import { hashToScalar } from './mimc.js'
import { verifyDLEQ } from './dleq.js'
import { mod, invMod } from './field.js'
import { bytesToBigInt, beToLe } from './bytes.js'
import type { OPRFRequest, OPRFResponse, Point } from './types.js'

function getRandomScalar(): bigint {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  let value = 0n
  for (let i = 0; i < 32; i++) {
    value = (value << 8n) | BigInt(bytes[i])
  }
  return mod(value, CURVE_ORDER)
}

function bigintToBytes(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array(0)
  const hex = n.toString(16)
  const paddedHex = hex.length % 2 === 0 ? hex : '0' + hex
  const bytes = new Uint8Array(paddedHex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(paddedHex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

function hashToCurve(elem0Bytes: Uint8Array, elem1Bytes: Uint8Array, domainBytes: Uint8Array): Point {
  // Empty bytes become [0] for hashing
  const input0 = elem0Bytes.length === 0 ? new Uint8Array([0]) : elem0Bytes
  const input1 = elem1Bytes.length === 0 ? new Uint8Array([0]) : elem1Bytes

  const scalar = hashToScalar([input0, input1, domainBytes])
  return scalarMul(BASE_POINT, scalar)
}

export function generateOPRFRequest(secretBytes: Uint8Array, domainSeparator: string): OPRFRequest {
  if (secretBytes.length > BYTES_PER_ELEMENT * 2) {
    throw new Error(`Secret too large: ${secretBytes.length} bytes, max ${BYTES_PER_ELEMENT * 2}`)
  }

  const domainBytes = new TextEncoder().encode(domainSeparator)
  if (domainBytes.length > BYTES_PER_ELEMENT) {
    throw new Error(`Domain separator too large: ${domainBytes.length} bytes, max ${BYTES_PER_ELEMENT}`)
  }

  // Split secret into two elements
  let elem0: bigint
  let elem1: bigint

  if (secretBytes.length > BYTES_PER_ELEMENT) {
    elem0 = bytesToBigInt(beToLe(secretBytes.slice(0, BYTES_PER_ELEMENT)))
    elem1 = bytesToBigInt(beToLe(secretBytes.slice(BYTES_PER_ELEMENT)))
  } else {
    elem0 = bytesToBigInt(beToLe(secretBytes))
    elem1 = 0n
  }

  // Hash to curve
  const H = hashToCurve(bigintToBytes(elem0), bigintToBytes(elem1), domainBytes)

  // Generate random mask (retry if 0, though practically never happens)
  let mask = getRandomScalar()
  while (mask === 0n) {
    mask = getRandomScalar()
  }

  // Mask the point
  const masked = scalarMul(H, mask)

  return {
    mask,
    maskedData: marshalPoint(masked),
    secretElements: [elem0, elem1],
  }
}

export function finalizeOPRF(
  serverPublicKey: Uint8Array,
  request: OPRFRequest,
  response: OPRFResponse
): { nullifier: bigint } {
  // Unmarshal points
  const serverPk = unmarshalPoint(serverPublicKey)
  const evaluated = unmarshalPoint(response.evaluated)
  const masked = unmarshalPoint(request.maskedData)

  // Parse c and r from bytes
  const c = bytesToBigInt(response.c)
  const r = bytesToBigInt(response.r)

  // Verify DLEQ proof
  if (!verifyDLEQ(c, r, serverPk, evaluated, masked)) {
    throw new Error('DLEQ proof verification failed')
  }

  // Deblind
  const invMask = invMod(request.mask, CURVE_ORDER)
  const deblinded = scalarMul(evaluated, invMask)

  // Final hash
  const elem0Bytes = bigintToBytes(request.secretElements[0])
  const elem1Bytes = bigintToBytes(request.secretElements[1])
  const xBytes = bigintToBytes(deblinded.x)
  const yBytes = bigintToBytes(deblinded.y)

  // Empty bytes become [0]
  const input0 = xBytes.length === 0 ? new Uint8Array([0]) : xBytes
  const input1 = yBytes.length === 0 ? new Uint8Array([0]) : yBytes
  const input2 = elem0Bytes.length === 0 ? new Uint8Array([0]) : elem0Bytes
  const input3 = elem1Bytes.length === 0 ? new Uint8Array([0]) : elem1Bytes

  const nullifier = hashToScalar([input0, input1, input2, input3])

  return { nullifier }
}
