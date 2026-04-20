# 1. Record Architecture Decisions

Status: Accepted
Date: 2026-01-25
Deciders: MCP Sentinel Team

## Context and Problem Statement

We need a way to track important architectural decisions, their context, and consequences. CMMI Level 5 requires formal Decision Analysis Records (DARs), but these are too heavy for our agile workflow.

## Decision Drivers

* Need for lightweight decision tracking
* Compliance with "Lean CMMI" goals
* Knowledge sharing across the team
* History of why decisions were made

## Decision Outcome

Chosen option: "Use Architecture Decision Records (ADRs)", because it provides a structured yet lightweight way to capture decisions in the codebase.

### Positive Consequences

* Decisions are version controlled with code
* Low friction to create
* Clear template to follow

### Negative Consequences

* Requires discipline to write them
* Can become stale if not maintained

## Pros and Cons of the Options

### Use ADRs

* Good, because it lives in git
* Good, because it is standard industry practice
* Bad, because it is text-based and not a database (harder to query)

### Use Formal DARs (Word/Excel)

* Good, because it is familiar to traditional auditors
* Bad, because it is separate from code
* Bad, because it is high friction

### Do Nothing

* Good, because zero effort
* Bad, because we lose context and history
