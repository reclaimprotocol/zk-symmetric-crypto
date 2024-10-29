<div>
    <div>
        <img src="https://raw.githubusercontent.com/reclaimprotocol/.github/main/assets/banners/Circom.png"  />
    </div>
</div>

This library contains zero-knowledge proof circuits for symmetric crypto operations. The goal is to enable a user to prove that they have the key to a symmetric encrypted message without revealing the key.

The following algorithms are supported:
- `chacha20`
- `aes-256-ctr`
- `aes-128-ctr`
	- which includes any CTR implementation. For eg. aes-256-gcm
	- note: this is a WIP, and may be insecure (borrowed implementation from [electron labs](https://github.com/Electron-Labs/aes-circom))

The library implements multiple ZK proof systems:
- [circom circuits](/circom/) backed by `snarkjs` (groth16).
- [`gnark` frontend circuits](/gnark/) backed by `gnark` (groth16)
- [`gnark` frontend circuits](/expander/) backed by `expander` (groth16)

All these proof systems can be accessed easily via a single [js](/js) package. The package provides easy-to-use abstract interfaces for generating & verifying proofs.

If you're just looking to use this library for your project, head to the [js package's readme](/js/readme.md).

## Contributing to Our Project

We're excited that you're interested in contributing to our project! Before you get started, please take a moment to review the following guidelines.

## Code of Conduct

Please read and follow our [Code of Conduct](https://github.com/reclaimprotocol/.github/blob/main/Code-of-Conduct.md) to ensure a positive and inclusive environment for all contributors.

## Security

If you discover any security-related issues, please refer to our [Security Policy](https://github.com/reclaimprotocol/.github/blob/main/SECURITY.md) for information on how to responsibly disclose vulnerabilities.

## Contributor License Agreement

Before contributing to this project, please read and sign our [Contributor License Agreement (CLA)](https://github.com/reclaimprotocol/.github/blob/main/CLA.md).

## Indie Hackers

For Indie Hackers: [Check out our guidelines and potential grant opportunities](https://github.com/reclaimprotocol/.github/blob/main/Indie-Hackers.md)

## License

This project is licensed under a [custom license](https://github.com/reclaimprotocol/.github/blob/main/LICENSE). By contributing to this project, you agree that your contributions will be licensed under its terms.

Thank you for your contributions!
