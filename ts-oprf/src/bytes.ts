/**
 * Shared byte conversion utilities.
 */

/**
 * Convert big-endian bytes to bigint.
 */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  if (bytes.length === 0) return 0n
  let result = 0n
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i])
  }
  return result
}

/**
 * Reverse byte array (big-endian to little-endian or vice versa).
 */
export function beToLe(bytes: Uint8Array): Uint8Array {
  const result = new Uint8Array(bytes.length)
  for (let i = 0; i < bytes.length; i++) {
    result[i] = bytes[bytes.length - 1 - i]
  }
  return result
}
