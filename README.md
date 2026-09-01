# SupplyChainGate

SupplyChainGate is a standalone GenLayer Intelligent Contract that evaluates an
immutable SPDX or CycloneDX software bill of materials (SBOM) against a reusable
on-chain software-supply-chain policy.

## Why GenLayer

SBOM fields are structured, but real admission decisions are semantic: license
expressions vary, component identities can be ambiguous, vulnerability entries
may lack severity, and policy language depends on distribution context.
SupplyChainGate uses comparative validator consensus for that interpretation and
then applies deterministic safety overrides before storing the result.

## Workflow

1. A builder creates a policy containing allowed and prohibited licenses,
   prohibited components, a maximum critical-vulnerability count, and required
   hash/supplier metadata.
2. A caller supplies an SPDX/CycloneDX artifact hosted in a public GitHub
   repository and locked to a full 40-character commit SHA.
3. Validators identify the artifact, compare its components and metadata with
   the policy, and return a structured assessment.
4. The contract normalizes and stores `ALLOW`, `REVIEW`, `BLOCK`, or
   `INSUFFICIENT_EVIDENCE` plus counts and matched findings.

## Deterministic safeguards

- Prohibited license or component matches always become `BLOCK`.
- Critical vulnerabilities over the policy cap always become `BLOCK`.
- Missing required hashes/suppliers or unresolved vulnerabilities prevent
  `ALLOW` and become `REVIEW`.
- Weak, empty, oversized, mutable, unsupported, zero-component, or unlocked
  evidence becomes `INSUFFICIENT_EVIDENCE`.
- Boolean, negative, malformed, and excessive count values are normalized
  safely; lists are deduplicated and bounded.
- Every interpolated value is framed as untrusted evidence to resist prompt
  injection.

## Public methods

- `create_policy(...)`
- `assess_sbom(policy_id, sbom_url, project_context)`
- `get_policy(policy_id)`
- `get_assessment(assessment_id)`
- `get_counts()`

## Verification

```powershell
python -B -m pytest -v
python -X utf8 -m genvm_linter.cli check contracts\supplychaingate.py
```

The suite contains direct tests plus two tests that execute the contract through
the GenVM test runtime with mocked web and validator responses.

## Deploy through GenLayer Studio

1. Connect a Bradbury-funded EVM wallet in GenLayer Studio.
2. Upload `contracts/supplychaingate.py`.
3. Deploy one instance and record its contract and transaction links.
4. Do not repeat a consensus write merely to create additional evidence.

## Originality scope

A targeted public search checked GenLayer SBOM, CycloneDX, SPDX, software supply
chain, license admission, and dependency-policy contracts. No close public
GenLayer match was found. This is a bounded public-source search, not a claim
about private or unindexed work.

## Limitations

- This contract assesses the submitted artifact; it does not generate an SBOM
  or independently scan package binaries.
- Vulnerability findings must be present in the immutable artifact (for example
  CycloneDX vulnerability or VEX entries).
- It supports public GitHub-hosted `.json`, `.spdx`, and `.cdx` artifacts.

## License

MIT
