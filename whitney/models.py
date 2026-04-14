"""Whitney finding model — stdlib dataclass, zero external dependencies.

This is a deliberate vendored copy of the field shape Whitney emits
into its `Finding` JSON output. It is NOT pydantic and has NO runtime
dependency on the parent Shasta project — Whitney ships standalone.

Downstream tools that consume Whitney findings can either:

  1. Read the JSON directly (the field names below are stable contract).
  2. Re-parse into their own richer model (e.g., Shasta's pydantic
     `Finding` model has the same field names so JSON round-trips
     cleanly).

If you need richer compliance framework enrichment (ISO 42001, EU AI
Act, NIST AI RMF), feed Whitney's JSON output into Shasta's compliance
mapper — the `check_id` field is the join key.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Finding severity. Matches Shasta's `shasta.evidence.models.Severity`."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceStatus(str, Enum):
    """Compliance status. Matches Shasta's status enum."""

    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    NOT_ASSESSED = "not_assessed"


class CheckDomain(str, Enum):
    """Check domain. Whitney findings are always AI_GOVERNANCE."""

    CLOUD_INFRASTRUCTURE = "cloud_infrastructure"
    AI_GOVERNANCE = "ai_governance"
    APPLICATION_SECURITY = "application_security"


@dataclass
class Finding:
    """A single Whitney scan finding.

    Fields are a deliberate subset of Shasta's pydantic `Finding` so the
    JSON representation round-trips between the two projects without a
    custom adapter.
    """

    check_id: str
    title: str
    description: str
    severity: Severity
    status: ComplianceStatus
    domain: CheckDomain
    resource_type: str
    resource_id: str
    region: str
    account_id: str
    remediation: str = ""
    soc2_controls: list[str] = field(default_factory=list)
    cis_aws_controls: list[str] = field(default_factory=list)
    cis_azure_controls: list[str] = field(default_factory=list)
    mcsb_controls: list[str] = field(default_factory=list)
    iso27001_controls: list[str] = field(default_factory=list)
    hipaa_controls: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict (JSON-friendly)."""
        return {
            "check_id": self.check_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "domain": self.domain.value,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "region": self.region,
            "account_id": self.account_id,
            "remediation": self.remediation,
            "soc2_controls": list(self.soc2_controls),
            "cis_aws_controls": list(self.cis_aws_controls),
            "cis_azure_controls": list(self.cis_azure_controls),
            "mcsb_controls": list(self.mcsb_controls),
            "iso27001_controls": list(self.iso27001_controls),
            "hipaa_controls": list(self.hipaa_controls),
            "details": dict(self.details),
        }
