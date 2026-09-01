# GenLayer Portal Submission

## Contribution

**Type:** Builder -> Intelligent Contracts

**Title:** SupplyChainGate - Consensus-Based SBOM Admission Policy

## Description

SupplyChainGate is a reusable GenLayer Intelligent Contract that evaluates an
immutable SPDX or CycloneDX software bill of materials against an on-chain
supply-chain admission policy. Builders define allowed and prohibited licenses,
prohibited components, a critical-vulnerability cap, and required component
hash/supplier metadata. Callers submit a public GitHub SBOM locked to a full
40-character commit SHA plus the product's deployment context. Comparative
validator consensus identifies the SBOM format, components, licenses,
vulnerabilities, and metadata gaps; deterministic safeguards then block any
prohibited license/component or critical count over the cap, prevent ALLOW when
required hashes/suppliers or vulnerability severity are unresolved, and fail
safely on empty, oversized, mutable, malformed, zero-component, or unlocked
evidence. Structured ALLOW, REVIEW, BLOCK, or INSUFFICIENT_EVIDENCE assessments
remain readable on-chain. Useful for release pipelines, registries, DAOs, and
agentic software procurement without relying on a centralized reviewer.

## Evidence

- GitHub repository: https://github.com/jasonmirza1/genlayer-supplychaingate
- Immutable contract source: https://github.com/jasonmirza1/genlayer-supplychaingate/blob/5a088c748d9c95a86a137252f87bc49e0e8206f9/contracts/supplychaingate.py
- Tests: https://github.com/jasonmirza1/genlayer-supplychaingate/tree/5a088c748d9c95a86a137252f87bc49e0e8206f9/tests
- Bradbury contract: https://explorer-bradbury.genlayer.com/address/0x1F828e15bF8C1702fD0f43830C75b98cC06f4fDA
- Deployment transaction: https://explorer-bradbury.genlayer.com/tx/0x105b2fe8afe63559fd77fcb723f876e3b46d94c22ad3abbba6ea6b3e989393f0

## Verification

- 48 tests passed (46 direct and 2 GenVM-runtime integration tests)
- GenVM lint and contract validation passed
- 5 public methods (2 write and 3 view)
