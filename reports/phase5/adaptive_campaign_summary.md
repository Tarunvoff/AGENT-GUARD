# AgentGuard Adaptive Offensive Validation Scorecard

- **Campaign ID**: `camp_adapt_20260919_110400`
- **Target System**: `agentguard-demo`
- **Campaign Seed**: `20260919`
- **Total Attack Executions**: 20 (Unique Variants: 20)
- **Attacks Blocked**: 20 (100.0%)
- **Attacks Bypassed**: 0
- **Sensitive Database Executions**: 0
- **Empirical Prevention Rate**: 100.0%
- **Max Mutation Depth**: 3 (Average: 1.9)
- **Mean Latency**: 0.63 ms (p95: 1.05 ms)
- **Pipeline Availability**: AI Secura (100.0%) | APIRIS (100.0%)

## Attack Family Coverage Breakdown

| Attack Type | Total | Blocked | Bypassed |
|---|---|---|---|
| `context_manipulation` | 10 | 10 | 0 |
| `data_exfiltration` | 10 | 10 | 0 |

## Defense Reasons Breakdown

| Defense Reason Code | Count |
|---|---|
| `TAINTED_CONTEXT_INTO_SENSITIVE_SINK` | 20 |