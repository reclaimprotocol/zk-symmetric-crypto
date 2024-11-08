export type KeyShare = {
    index: number
    publicKey: Uint8Array
    privateKey: Uint8Array
}

export type KeygenResult = {
    publicKey: Uint8Array
    privateKey: Uint8Array
    shares: KeyShare[]
}

export type OPRFRequestData = {
    mask: Uint8Array
    maskedData: Uint8Array
    secretElements: Uint8Array[]
}

export type OPRFResponseData = {
    evaluated: Uint8Array
    c: Uint8Array
    r: Uint8Array
}

export type TOPRFResponseData = OPRFResponseData & {
    index: number
    publicKeyShare: Uint8Array
}
