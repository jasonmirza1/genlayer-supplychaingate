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

- GitHub repository: pending
- Immutable contract source: pending
- Tests: pending
- Bradbury contract: pending
- Deployment transaction: pending

## Verification

- 41 tests passed (39 direct and 2 GenVM-runtime integration tests)
- GenVM lint and contract validation passed
- 5 public methods (2 write and 3 view)
