/**
 * A point on the BabyJubJub elliptic curve.
 * Coordinates are bigints in the BN254 scalar field.
 */
export interface Point {
  /** X coordinate (field element) */
  x: bigint
  /** Y coordinate (field element) */
  y: bigint
}

/**
 * Client-side OPRF request data.
 * Contains the masked point and secret data needed for finalization.
 */
export interface OPRFRequest {
  /** Random blinding factor used to mask the input point */
  mask: bigint
  /** Compressed 32-byte encoding of the masked curve point */
  maskedData: Uint8Array
  /** Original secret split into two field elements [elem0, elem1] */
  secretElements: [bigint, bigint]
}

/**
 * Server response to an OPRF request.
 * Contains the evaluated point and DLEQ proof components.
 */
export interface OPRFResponse {
  /** Server's public key share (compressed 32-byte point) */
  publicKeyShare: Uint8Array
  /** Evaluated point: serverSk * maskedPoint (compressed 32-byte point) */
  evaluated: Uint8Array
  /** DLEQ proof challenge (big-endian bytes) */
  c: Uint8Array
  /** DLEQ proof response (big-endian bytes) */
  r: Uint8Array
}

/**
 * Final OPRF output after client-side finalization.
 */
export interface OPRFOutput {
  /** Deterministic nullifier derived from the OPRF evaluation */
  nullifier: bigint
}
