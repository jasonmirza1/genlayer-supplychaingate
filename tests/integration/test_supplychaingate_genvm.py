import json
from pathlib import Path

import pytest


pytestmark = pytest.mark.integration
SHA = "b" * 40
SBOM_URL = f"https://github.com/example/product/blob/{SHA}/artifacts/sbom.cdx.json"


def _deploy(direct_deploy_compat):
    path = Path(__file__).parents[2] / "contracts" / "supplychaingate.py"
    return direct_deploy_compat(str(path))


def _policy(contract):
    return contract.create_policy(
        "Production admission",
        "MIT, Apache-2.0, BSD-2-Clause, and BSD-3-Clause.",
        "AGPL variants and licenses with unknown redistribution terms.",
        "Components named malware-demo or packages from unapproved registries.",
        0, True, True,
    )


def test_policy_and_sbom_assessment_execute_through_genvm(direct_vm, direct_deploy_compat):
    direct_vm.mock_web(
        r".*raw\.githubusercontent\.com/example/product/b{40}/artifacts/sbom\.cdx\.json.*",
        {"status": 200, "body": '{"bomFormat":"CycloneDX","components":[{"name":"safe-lib"}]}'},
    )
    direct_vm.mock_llm(
        r".*Evaluate an immutable software bill of materials.*",
        json.dumps({
            "decision": "ALLOW", "evidence_quality": "ENOUGH",
            "revision_verified": True, "is_sbom": True,
            "sbom_format": "CycloneDX 1.6", "component_count": 1,
            "critical_vulnerability_count": 0, "missing_hash_count": 0,
            "missing_supplier_count": 0, "summary": "Policy compliant.",
            "prohibited_license_matches": [], "prohibited_component_matches": [],
            "unresolved_vulnerabilities": [],
        }),
    )
    contract = _deploy(direct_deploy_compat)
    _policy(contract)
    result = contract.assess_sbom(
        "1", SBOM_URL,
        "Production web service distributed as a commercial hosted application.",
    )
    assert result["decision"] == "ALLOW"
    assert result["component_count"] == 1
    assert contract.get_counts() == {"policies": 1, "assessments": 1}


def test_oversized_sbom_guard_executes_through_genvm(direct_vm, direct_deploy_compat):
    direct_vm.mock_web(
        r".*raw\.githubusercontent\.com/example/product/b{40}/artifacts/sbom\.cdx\.json.*",
        {"status": 200, "body": "x" * 16001},
    )
    contract = _deploy(direct_deploy_compat)
    _policy(contract)
    result = contract.assess_sbom(
        "1", SBOM_URL,
        "Production web service distributed as a commercial hosted application.",
    )
    assert result["decision"] == "INSUFFICIENT_EVIDENCE"
    assert result["revision_verified"] is False
