export interface Point {
  x: bigint
  y: bigint
}

export interface OPRFRequest {
  mask: bigint
  maskedData: Uint8Array
  secretElements: [bigint, bigint]
}

export interface OPRFResponse {
  publicKeyShare: Uint8Array
  evaluated: Uint8Array
  c: Uint8Array
  r: Uint8Array
}

export interface OPRFOutput {
  nullifier: bigint
}
