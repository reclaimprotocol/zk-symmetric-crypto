/**
 * Integration test for ts-oprf against actual attestor-core server.
 *
 * Prerequisites:
 * - Attestor server running at localhost:8001
 * - Run with: npm run test:integration
 *
 * This test uses a minimal WebSocket client with manual protobuf encoding
 * to avoid ESM/CJS compatibility issues with attestor-core.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { generateOPRFRequest, finalizeOPRF } from '../src/oprf.js'
import type { OPRFRequest, OPRFResponse } from '../src/types.js'
import WebSocket from 'ws'

const ATTESTOR_URL = process.env.ATTESTOR_URL || 'ws://localhost:8001/ws'
const ZK_ENGINE_GNARK = 1

// Minimal protobuf encoding helpers
function encodeVarint(value: number): Uint8Array {
  const bytes: number[] = []
  while (value > 0x7f) {
    bytes.push((value & 0x7f) | 0x80)
    value >>>= 7
  }
  bytes.push(value)
  return new Uint8Array(bytes)
}

function encodeField(fieldNumber: number, wireType: number, data: Uint8Array): Uint8Array {
  const tag = encodeVarint((fieldNumber << 3) | wireType)
  if (wireType === 2) {
    // Length-delimited
    const length = encodeVarint(data.length)
    const result = new Uint8Array(tag.length + length.length + data.length)
    result.set(tag, 0)
    result.set(length, tag.length)
    result.set(data, tag.length + length.length)
    return result
  } else if (wireType === 0) {
    // Varint
    const result = new Uint8Array(tag.length + data.length)
    result.set(tag, 0)
    result.set(data, tag.length)
    return result
  }
  throw new Error(`Unsupported wire type: ${wireType}`)
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0)
  const result = new Uint8Array(totalLength)
  let offset = 0
  for (const arr of arrays) {
    result.set(arr, offset)
    offset += arr.length
  }
  return result
}

// Encode TOPRFRequest message
function encodeTOPRFRequest(maskedData: Uint8Array, engine: number): Uint8Array {
  return concat(
    encodeField(1, 2, maskedData), // maskedData
    encodeField(2, 0, encodeVarint(engine)) // engine
  )
}

// Encode RPCMessage with toprfRequest
function encodeRPCMessage(id: number, toprfRequest: Uint8Array): Uint8Array {
  return concat(
    encodeField(1, 0, encodeVarint(id)), // id
    encodeField(18, 2, toprfRequest) // toprfRequest (field 18)
  )
}

// Encode InitRequest message
function encodeInitRequest(): Uint8Array {
  // clientVersion = 5 (ATTESTOR_VERSION_3_0_0) - field 2
  // signatureType = 1 (SERVICE_SIGNATURE_TYPE_ETH) - field 3
  return concat(
    encodeField(2, 0, encodeVarint(5)), // clientVersion (field 2)
    encodeField(3, 0, encodeVarint(1)) // signatureType (field 3)
  )
}

// Encode RPCMessage with initRequest
function encodeInitRPCMessage(id: number): Uint8Array {
  const initRequest = encodeInitRequest()
  return concat(
    encodeField(1, 0, encodeVarint(id)), // id (field 1)
    encodeField(2, 2, initRequest) // initRequest (field 2)
  )
}

// Encode RPCMessages (container)
function encodeRPCMessages(...messages: Uint8Array[]): Uint8Array {
  let result = new Uint8Array(0)
  for (const msg of messages) {
    result = concat(result, encodeField(1, 2, msg))
  }
  return result
}

// Debug logging (enable with DEBUG_TESTS=1)
const debug = process.env.DEBUG_TESTS
  ? (...args: unknown[]) => console.log(...args)
  : () => {}

// Decode varint from buffer with bounds checking
function decodeVarint(buffer: Uint8Array, offset: number): { value: number; bytesRead: number } {
  let value = 0
  let shift = 0
  let bytesRead = 0
  const maxBytes = 5 // 32-bit varint max
  while (offset + bytesRead < buffer.length && bytesRead < maxBytes) {
    const byte = buffer[offset + bytesRead]
    value |= (byte & 0x7f) << shift
    bytesRead++
    if ((byte & 0x80) === 0) break
    shift += 7
  }
  if (bytesRead === 0) {
    throw new Error('Unexpected end of buffer while decoding varint')
  }
  if (bytesRead === maxBytes && (buffer[offset + bytesRead - 1] & 0x80) !== 0) {
    throw new Error('Varint too long')
  }
  return { value, bytesRead }
}

// Decode protobuf fields from buffer
function decodeFields(buffer: Uint8Array): Map<number, Uint8Array | number> {
  const fields = new Map<number, Uint8Array | number>()
  let offset = 0
  while (offset < buffer.length) {
    const { value: tag, bytesRead: tagBytes } = decodeVarint(buffer, offset)
    offset += tagBytes
    const fieldNumber = tag >>> 3
    const wireType = tag & 0x7

    if (wireType === 0) {
      // Varint
      const { value, bytesRead } = decodeVarint(buffer, offset)
      offset += bytesRead
      fields.set(fieldNumber, value)
    } else if (wireType === 2) {
      // Length-delimited
      const { value: length, bytesRead } = decodeVarint(buffer, offset)
      offset += bytesRead
      fields.set(fieldNumber, buffer.slice(offset, offset + length))
      offset += length
    } else {
      throw new Error(`Unsupported wire type: ${wireType}`)
    }
  }
  return fields
}

// Skip test if attestor is not running
const attestorAvailable = async (): Promise<boolean> => {
  return new Promise((resolve) => {
    const ws = new WebSocket(ATTESTOR_URL)
    const timeout = setTimeout(() => {
      ws.close()
      resolve(false)
    }, 2000)
    ws.on('open', () => {
      clearTimeout(timeout)
      ws.close()
      resolve(true)
    })
    ws.on('error', () => {
      clearTimeout(timeout)
      resolve(false)
    })
  })
}

interface AttestorConnection {
  ws: WebSocket
  serverPublicKey: Uint8Array
  nextId: number
  sendToprf: (maskedData: Uint8Array) => Promise<{
    publicKeyShare: Uint8Array
    evaluated: Uint8Array
    c: Uint8Array
    r: Uint8Array
  }>
  close: () => void
}

async function connectToAttestor(): Promise<AttestorConnection> {
  return new Promise((resolve, reject) => {
    const initId = 1
    const initRequest = encodeInitRPCMessage(initId)
    const initMessages = encodeRPCMessages(initRequest)
    const initB64 = Buffer.from(initMessages).toString('base64')

    const url = new URL(ATTESTOR_URL)
    url.searchParams.set('messages', initB64)

    const ws = new WebSocket(url.toString())
    let serverPublicKey: Uint8Array | null = null
    let nextId = 2

    const pendingRequests = new Map<number, {
      resolve: (data: any) => void
      reject: (err: Error) => void
    }>()

    ws.on('error', (err) => {
      reject(err)
    })

    ws.on('message', (data: Buffer) => {
      try {
        const messages = decodeFields(data)
        // RPCMessages has repeated RPCMessage at field 1
        // We need to handle multiple messages
        for (const [fieldNum, value] of messages) {
          if (fieldNum === 1 && value instanceof Uint8Array) {
            const rpcMsg = decodeFields(value)
            const msgId = rpcMsg.get(1) as number

            // Check for initResponse (field 3)
            const initResponse = rpcMsg.get(3)
            if (initResponse instanceof Uint8Array) {
              const initFields = decodeFields(initResponse)
              serverPublicKey = initFields.get(1) as Uint8Array
              debug('Init response received, public key:', Buffer.from(serverPublicKey).toString('hex'))
              resolve({
                ws,
                serverPublicKey,
                nextId,
                sendToprf: async (maskedData: Uint8Array) => {
                  const reqId = nextId++
                  const toprfReq = encodeTOPRFRequest(maskedData, ZK_ENGINE_GNARK)
                  const rpcMsg = encodeRPCMessage(reqId, toprfReq)
                  const rpcMsgs = encodeRPCMessages(rpcMsg)

                  return new Promise((res, rej) => {
                    pendingRequests.set(reqId, { resolve: res, reject: rej })
                    ws.send(rpcMsgs)
                  })
                },
                close: () => ws.close()
              })
            }

            // Check for toprfResponse (field 19)
            const toprfResponse = rpcMsg.get(19)
            if (toprfResponse instanceof Uint8Array) {
              const toprfFields = decodeFields(toprfResponse)
              debug('TOPRF Response raw fields:')
              for (const [fieldNum, value] of toprfFields) {
                if (value instanceof Uint8Array) {
                  debug(`  field ${fieldNum}: ${Buffer.from(value).toString('hex')} (${value.length} bytes)`)
                } else {
                  debug(`  field ${fieldNum}: ${value}`)
                }
              }
              const pending = pendingRequests.get(msgId)
              if (pending) {
                pendingRequests.delete(msgId)
                pending.resolve({
                  publicKeyShare: toprfFields.get(1) as Uint8Array,
                  evaluated: toprfFields.get(2) as Uint8Array,
                  c: toprfFields.get(3) as Uint8Array,
                  r: toprfFields.get(4) as Uint8Array,
                })
              }
            }

            // Check for error (field 5 = requestError)
            const errorData = rpcMsg.get(5)
            if (errorData instanceof Uint8Array) {
              const errorFields = decodeFields(errorData)
              const errorCode = errorFields.get(1) as number
              const errorMsg = errorFields.get(2)
              const pending = pendingRequests.get(msgId)
              if (pending) {
                pendingRequests.delete(msgId)
                const msgStr = errorMsg instanceof Uint8Array
                  ? new TextDecoder().decode(errorMsg)
                  : String(errorMsg || 'Unknown error')
                pending.reject(new Error(`Attestor error ${errorCode}: ${msgStr}`))
              }
            }
          }
        }
      } catch (err) {
        console.error('Error parsing message:', err)
      }
    })

    ws.on('close', () => {
      for (const pending of pendingRequests.values()) {
        pending.reject(new Error('Connection closed'))
      }
      pendingRequests.clear()
    })

    setTimeout(() => {
      if (!serverPublicKey) {
        ws.close()
        reject(new Error('Timeout waiting for init response'))
      }
    }, 5000)
  })
}

describe.skipIf(!(await attestorAvailable()))('Integration with attestor-core', () => {
  let conn: AttestorConnection

  beforeAll(async () => {
    conn = await connectToAttestor()
  })

  afterAll(() => {
    conn?.close()
  })

  it('should complete OPRF flow with real attestor', async () => {
    const secret = new TextEncoder().encode('test@example.com')
    const domainSeparator = 'reclaim-test'

    // Generate request using our ts-oprf library
    const request: OPRFRequest = generateOPRFRequest(secret, domainSeparator)

    debug('Sending OPRF request...')
    debug('  maskedData:', Buffer.from(request.maskedData).toString('hex'))

    // Send TOPRF request to attestor
    const response = await conn.sendToprf(request.maskedData)

    debug('Received OPRF response')

    // Build response object
    const oprfResponse: OPRFResponse = {
      publicKeyShare: response.publicKeyShare,
      evaluated: response.evaluated,
      c: response.c,
      r: response.r,
    }

    // Finalize OPRF using publicKeyShare from response
    const output = finalizeOPRF(response.publicKeyShare, request, oprfResponse)

    debug('OPRF output (nullifier):', output.nullifier.toString())

    // Verify output is valid
    expect(output.nullifier).toBeGreaterThan(0n)
    expect(output.nullifier).toBeDefined()

    // Verify determinism - same inputs should give same output
    const output2 = finalizeOPRF(response.publicKeyShare, request, oprfResponse)
    expect(output2.nullifier).toBe(output.nullifier)
  })

  it('should produce different nullifiers for different inputs', async () => {
    const secret1 = new TextEncoder().encode('user1@example.com')
    const secret2 = new TextEncoder().encode('user2@example.com')
    const domainSeparator = 'reclaim-test'

    // Generate requests
    const request1 = generateOPRFRequest(secret1, domainSeparator)
    const request2 = generateOPRFRequest(secret2, domainSeparator)

    // Send to attestor
    const [response1, response2] = await Promise.all([
      conn.sendToprf(request1.maskedData),
      conn.sendToprf(request2.maskedData),
    ])

    // Finalize
    const output1 = finalizeOPRF(conn.serverPublicKey, request1, {
      publicKeyShare: response1.publicKeyShare,
      evaluated: response1.evaluated,
      c: response1.c,
      r: response1.r,
    })

    const output2 = finalizeOPRF(conn.serverPublicKey, request2, {
      publicKeyShare: response2.publicKeyShare,
      evaluated: response2.evaluated,
      c: response2.c,
      r: response2.r,
    })

    debug('Nullifier 1:', output1.nullifier.toString())
    debug('Nullifier 2:', output2.nullifier.toString())

    // Different inputs should produce different nullifiers
    expect(output1.nullifier).not.toBe(output2.nullifier)
  })

  it('should produce same nullifier for same input with different masks', async () => {
    const secret = new TextEncoder().encode('consistent@example.com')
    const domainSeparator = 'reclaim-test'

    // Generate two requests (different random masks)
    const request1 = generateOPRFRequest(secret, domainSeparator)
    const request2 = generateOPRFRequest(secret, domainSeparator)

    // Masks should be different
    expect(request1.mask).not.toBe(request2.mask)

    // Send to attestor
    const [response1, response2] = await Promise.all([
      conn.sendToprf(request1.maskedData),
      conn.sendToprf(request2.maskedData),
    ])

    // Finalize both
    const output1 = finalizeOPRF(conn.serverPublicKey, request1, {
      publicKeyShare: response1.publicKeyShare,
      evaluated: response1.evaluated,
      c: response1.c,
      r: response1.r,
    })

    const output2 = finalizeOPRF(conn.serverPublicKey, request2, {
      publicKeyShare: response2.publicKeyShare,
      evaluated: response2.evaluated,
      c: response2.c,
      r: response2.r,
    })

    debug('Same input, different masks:')
    debug('  Nullifier 1:', output1.nullifier.toString())
    debug('  Nullifier 2:', output2.nullifier.toString())

    // Same input should produce same nullifier regardless of mask
    expect(output1.nullifier).toBe(output2.nullifier)
  })
})
