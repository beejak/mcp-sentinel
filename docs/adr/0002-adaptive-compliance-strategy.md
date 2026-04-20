# 2. Adaptive Compliance Strategy

Date: 2026-01-25

## Status

Accepted

## Context

The project initially aimed for **CMMI Level 5** certification. However, the overhead of maintaining formal process areas (CAR, OPM, DAR) and their associated documentation artifacts is disproportionately high for a rapid-development environment. The team requires a compliance framework that ensures quality and security without slowing down velocity.

## Decision

We will replace the formal CMMI Level 5 goal with an **Adaptive Compliance Strategy** based on three pillars:

1.  **Governance as Code**:
    *   Replace formal Decision Analysis Resolution (DAR) with **Architecture Decision Records (ADRs)** stored in Git.
    *   Replace Process Asset Library (PAL) with **Repo-based Documentation** (Markdown).

2.  **Continuous Verification**:
    *   Replace periodic process audits with **Automated CI/CD Gates**.
    *   Metrics (Coverage, Linting, Security) are collected automatically on every commit via `scripts/metrics.py`.

3.  **Automated Remediation**:
    *   Replace manual Defect Resolution with **Automated Fixers** (`mcp-sentinel fix`).
    *   Focus on "Mean Time to Remediate" (MTTR) rather than just defect prevention.

## Consequences

### Positive
*   **Reduced Overhead**: No manual maintenance of external compliance documents.
*   **Real-time Feedback**: Compliance status is visible on every PR.
*   **Developer Experience**: Compliance is integrated into the workflow (CLI, Git), not a separate administrative task.

### Negative
*   **Certification Gap**: We will not achieve formal CMMI certification (unless we map these artifacts to CMMI goals later).
*   **Tooling Dependence**: Heavily relies on the correctness of automated scripts and GitHub Actions.

## Compliance Mapping

| CMMI Process Area | Adaptive Equivalent |
|-------------------|---------------------|
| CAR (Causal Analysis and Resolution) | Blameless Post-Mortems (Markdown) |
| DAR (Decision Analysis and Resolution) | ADRs (Markdown) |
| OPM (Organizational Performance Mgmt) | DORA Metrics Dashboard |
| QPM (Quantitative Project Mgmt) | Automated Coverage/Lint Metrics |
