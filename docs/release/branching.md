# AgentGuard Branching & Release Strategy

## 1. Branch Architecture

To ensure strict preservation of working baselines and non-destructive release engineering, AgentGuard enforces the following branching model:

```
main (Production Release)
  └── actshield-enterprise (Phase 9 / Pre-release state)
        ├── agentguard/archive/current-state  <-- Immutable Archive
        └── agentguard-enterprise-release     <-- Active Enterprise Hardening & Release Branch
```

## 2. Archive Point

- **Archive Branch**: `agentguard/archive/current-state`
- **Base Commit**: `7167a80` (`test(embedded-dashboard): add test suite for embedded dashboard routes and API endpoints`)
- **Baseline Test Suite Status**: `252 passed, 4 skipped, 2 warnings in 11.32s`
- **Creation Date**: 2026-09-22

## 3. Engineering Rules

1. **No Force-Pushes**: `git push --force` is disabled on main, archive, and release branches.
2. **No Destructive History Rewrites**: Retain all legacy commit references and audit logs.
3. **Fail-Safe Merges**: Merges to `main` require green status on the full security and regression test suite, clean packaging build, and clean virtual environment wheel installation.
