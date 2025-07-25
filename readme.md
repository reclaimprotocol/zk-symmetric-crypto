<div align="center">
    <img src="https://raw.githubusercontent.com/reclaimprotocol/.github/main/assets/banners/Circom.png" alt="Circom Banner" />
</div>

# 🔒 Zero-Knowledge Proof Library

Welcome to our library for **zero-knowledge proof circuits** designed for symmetric crypto operations! 🚀 The goal is to allow users to prove they possess the key to a symmetric encrypted message without revealing the key itself.

## 📚 Table of Contents
- [🔒 Zero-Knowledge Proof Library](#-zero-knowledge-proof-library)
- [🛠️ Supported Algorithms](#-supported-algorithms)
- [🔍 ZK Proof Systems](#-zk-proof-systems)
- [🤝 Contributing to Our Project](#-contributing-to-our-project)
    - [📜 Code of Conduct](#-code-of-conduct)
    - [🔐 Security](#-security)
    - [✍️ Contributor License Agreement](#-contributor-license-agreement)
    - [🌱 Indie Hackers](#-indie-hackers)
- [📄 License](#-license)

## 🛠️ Supported Algorithms
We currently support the following algorithms:
- **`chacha20`**
- **`aes-256-ctr`**
- **`aes-128-ctr`**
    - This includes any CTR implementation (e.g., **aes-256-gcm**).
    - ⚠️ Note: This is a work in progress and may be insecure (borrowed implementation from [Electron Labs](https://github.com/Electron-Labs/aes-circom)).

## 🔍 ZK Proof Systems
Our library implements multiple ZK proof systems:
- **[Circom Circuits](/circom/)** backed by `snarkjs` (groth16).
- **[`gnark` Frontend Circuits](/gnark/)** backed by `gnark` (groth16).
- **[`gnark` Frontend Circuits](/expander/)** backed by `expander` (GKR):
    - Note: This is a work in progress and may be insecure. It is also only available for `chacha20` at the moment.

All these proof systems can be accessed easily via a single **[JS Package](/js)**. This package provides user-friendly abstract interfaces for generating and verifying proofs.

👉 If you’re just looking to integrate this library into your project, check out the **[JS Package's README](/js/readme.md)**.

## 🤝 Contributing to Our Project

We're thrilled that you're interested in contributing! 🎉 Before you get started, please review the following guidelines:

### 📜 Code of Conduct

To ensure a positive and inclusive environment for all contributors, please read and follow our [Code of Conduct](https://github.com/reclaimprotocol/.github/blob/main/Code-of-Conduct.md).

### 🔐 Security
If you discover any security-related issues, please refer to our [Security Policy](https://github.com/reclaimprotocol/.github/blob/main/SECURITY.md) for information on how to responsibly disclose vulnerabilities.

### ✍️ Contributor License Agreement

Before contributing to this project, please read and sign our [Contributor License Agreement (CLA)](https://github.com/reclaimprotocol/.github/blob/main/CLA.md).

### 🌱 Indie Hackers

For Indie Hackers: [Check out our guidelines and potential grant opportunities](https://github.com/reclaimprotocol/.github/blob/main/Indie-Hackers.md).

## 📊 Performance Benchmarks

### ChaCha20 Noir Circuit Benchmarks

The following benchmarks were conducted for ChaCha20 encryption using Noir circuits with 1KB data payload (8 proof chunks):

| ZK Proof System | Proof Generation Time | Test Command |
|---|---|---|
| **Barretenberg (Noir)** | ~70 seconds (8 proofs) | `cd js && npm run bench` |
| **Expander (Multi-thread)** | ~5 seconds (8 proofs) | `cd js && npm run bench` |

**Test Environment:**
- Data size: 1024 bytes
- Chunk size: 128 bytes per proof
- Total proofs generated: 8
- Algorithm: ChaCha20 symmetric encryption

**Running Benchmarks:**

```bash
# Run all benchmarks
cd js && npm run bench

# Run specific tests
cd js && npm test

# Run Circom circuit tests
cd circom && npm test

# Run Gnark tests
cd gnark && go test ./...
```

## 📄 License

This project is licensed under a [custom license](https://github.com/reclaimprotocol/.github/blob/main/LICENSE). By contributing, you agree that your contributions will be licensed under its terms.

---

Thank you for your contributions!
