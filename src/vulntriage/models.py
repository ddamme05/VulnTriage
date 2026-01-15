"""Pydantic models for VulnTriage data structures."""

from typing import Literal

from pydantic import BaseModel, Field

# Canonical status type used everywhere
TriageStatus = Literal["dismissed", "needs_review", "actionable"]


class Vulnerability(BaseModel):
    """A vulnerability from Trivy report."""

    vuln_id: str = Field(..., description="CVE or vulnerability ID")
    pkg_name: str = Field(..., description="Package name from Trivy")
    installed_version: str = Field(..., description="Currently installed version")
    fixed_version: str | None = Field(None, description="Version with fix, if available")
    severity: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN")
    title: str = Field("", description="Short description of the vulnerability")
    description: str = Field("", description="Full vulnerability description")
    # MVP: sourced from Trivy JSON
    cvss_score: float | None = Field(None, description="CVSS score from Trivy")
    # V2 enrichment fields
    proximity: Literal["direct", "transitive"] | None = Field(
        None, description="V2: Dependency proximity from lockfile analysis"
    )
    epss_score: float | None = Field(None, description="V2: EPSS exploitation probability")
    is_kev: bool = Field(False, description="V2: Is on CISA KEV list")


class EvidenceRef(BaseModel):
    """Reference to evidence in source code.

    The LLM outputs coordinates only—Python reads the actual snippet from disk.
    This prevents hallucinated code from appearing in the TUI.
    """

    file_path: str = Field(..., description="Path to the source file")
    line_start: int = Field(..., description="Starting line number (1-indexed)")
    line_end: int = Field(..., description="Ending line number (1-indexed, inclusive)")
    symbol_name: str = Field(..., description="The symbol being referenced")
    # NOTE: snippet is NOT stored here. Python populates it during display/enrichment
    # by reading the actual bytes from disk. This enforces the "Trust but Verify" model.


class AITriageRequest(BaseModel):
    """Request payload for AI triage analysis."""

    code_context: str = Field(
        ..., description="Code snippet around the call site (computed by Python)"
    )
    evidence: EvidenceRef = Field(..., description="Location of the call site")
    vulnerability: Vulnerability = Field(
        ..., description="The vulnerability being analyzed"
    )


class AITriageResponse(BaseModel):
    """Structured response from AI triage analysis."""

    is_exploitable: bool = Field(
        ..., description="Whether the vulnerability is likely exploitable"
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence score from 0 to 1"
    )
    reasoning: str = Field(..., description="Explanation of the analysis")
    cited_lines: list[int] = Field(
        default_factory=list, description="Line numbers cited as evidence"
    )
    suggested_fix: str | None = Field(
        None, description="Suggested remediation command, e.g., 'uv add requests==2.31.0'"
    )


class ScanResult(BaseModel):
    """Final scan result for a vulnerability.

    This is THE canonical output type - everything converges here.
    """

    vulnerability: Vulnerability
    status: TriageStatus = Field(..., description="Triage classification")
    reason: str = Field(..., description="Human-readable explanation")
    evidence: list[EvidenceRef] = Field(
        default_factory=list, description="Source code locations as evidence"
    )
    ai_analysis: AITriageResponse | None = Field(
        default=None, description="AI analysis if performed"
    )
