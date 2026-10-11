"""Application data, intentionally smaller than the CycloneDX document model."""

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator


class Decision(StrEnum):
    ALLOW = "Allow"
    NEEDS_REVIEW = "Needs review"
    REJECT = "Reject"


class LicenseDeclaration(BaseModel):
    kind: Literal["spdx", "name", "expression"]
    value: str
    pointer: str


class SourceReference(BaseModel):
    url: str | None
    kind: Literal["license", "model-card", "sbom-declaration"]
    pointer: str


class Component(BaseModel):
    component_id: str
    bom_ref: str | None = None
    name: str
    version: str | None = None
    type: str
    licenses: list[LicenseDeclaration] = Field(default_factory=list)
    sources: list[SourceReference] = Field(default_factory=list)


NonemptyString = Annotated[str, StringConstraints(min_length=1, pattern=r"\S")]


class FindingCode(StrEnum):
    MISSING_MODEL_CARD = "missing_model_card"
    AMBIGUOUS_MODEL_CARD = "ambiguous_model_card"
    UNSUPPORTED_SOURCE = "unsupported_source"
    UNAVAILABLE_SOURCE = "unavailable_source"
    MISSING_LICENSE = "missing_license"
    INVALID_METADATA = "invalid_metadata"
    CUSTOM_LICENSE = "custom_license"
    UNKNOWN_LICENSE = "unknown_license"
    RESTRICTED_LICENSE = "restricted_license"
    LICENSE_CONFLICT = "license_conflict"
    USAGE_CONTEXT = "usage_context"
    POTENTIAL_RESTRICTION = "potential_restriction"
    REFERENCED_TERMS_UNREAD = "referenced_terms_unread"
    NO_SUPPORTED_INDICATORS = "no_supported_indicators"


class EvidenceExcerpt(BaseModel):
    document_url: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    excerpt: str

    @model_validator(mode="after")
    def ordered_lines(self) -> Self:
        if self.line_end < self.line_start:
            raise ValueError("Evidence line_end must not precede line_start.")
        return self


class ModelFinding(BaseModel):
    code: FindingCode
    message: NonemptyString
    evidence: EvidenceExcerpt | None = None


class ModelAssessment(BaseModel):
    status: Literal["inspected", "unavailable", "unsupported"]
    document_url: str | None = None
    document_sha256: str | None = None
    card_license: str | None = None
    normalized_license: str | None = None
    license_policy_decision: Decision | None = None
    license_evidence: EvidenceExcerpt | None = None
    findings: list[ModelFinding] = Field(default_factory=list)


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: NonemptyString
    allowed: list[NonemptyString]
    review: list[NonemptyString]
    rejected: list[NonemptyString]

    @model_validator(mode="after")
    def unique_identifiers(self) -> Self:
        seen: set[str] = set()
        for category in (self.allowed, self.review, self.rejected):
            for identifier in category:
                if identifier in seen:
                    raise ValueError(f"Duplicate or overlapping policy identifier: {identifier}")
                seen.add(identifier)
        return self


class ComponentResult(BaseModel):
    component_id: str
    bom_ref: str | None
    name: str
    version: str | None
    type: str
    declared_licenses: list[str]
    decision: Decision
    reason: NonemptyString
    sources: list[SourceReference]
    model_assessment: ModelAssessment | None = None


class Summary(BaseModel):
    total: int
    allow: int
    needs_review: int
    reject: int


class ReviewResult(BaseModel):
    policy_version: str
    results: list[ComponentResult]
    summary: Summary
