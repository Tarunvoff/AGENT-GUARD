# ActShield / AgentGuard — Enterprise Security Console Design System

**Version:** 2.0.0 (Enterprise Light-First Specification)  
**Standard:** Information-Dense, Structured, Fail-Safe Security Operations Console  
**Reference Alignment:** Cloudflare Dashboard, Datadog Security, AWS Security Hub, Microsoft Defender for Cloud

---

## 1. Core Principles

1. **Information Density over Decoration**: Security operators require rapid scanning, structured data, and high signal-to-noise ratio.
2. **Neutral Surfaces with Semantic Accents**: White/slate surfaces with controlled, high-contrast semantic accents for severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and enforcement (`BLOCK`, `ALLOW`, `HITL`, `MONITOR`).
3. **Tables over Cards**: Tabular layouts with sorting, filtering, and right-side inspection drawers provide optimal cognitive clarity.
4. **Purposeful Animation Only**: Animations are strictly limited to active loading spinners and live status indicator pulses. No decorative transitions.
5. **Deterministic Execution Truth**: Every security event explicitly demonstrates the 4-point execution invariant (`INTENDED`, `REQUESTED`, `ALLOWED`, `EXECUTED`).

---

## 2. Color System

### 2.1 Surface Palette
| Token | Hex Value | Role |
|---|---|---|
| `--surface-bg` | `#F8FAFC` (slate-50) | Global application canvas background |
| `--surface-base` | `#FFFFFF` | Primary card, table, and panel surface |
| `--surface-raised` | `#F1F5F9` (slate-100) | Toolbars, table headers, and badges |
| `--surface-border` | `#E2E8F0` (slate-200) | Subtle container and card boundaries |
| `--surface-border-strong` | `#CBD5E1` (slate-300) | Interactive focus and highlighted borders |
| `--surface-hover` | `#F8FAFC` (slate-50) | Table row hover background |

### 2.2 Typography Palette
| Token | Hex Value | Role |
|---|---|---|
| `--text-primary` | `#0F172A` (slate-900) | Headings, titles, and high-emphasis labels |
| `--text-secondary` | `#334155` (slate-700) | Body copy and table text |
| `--text-tertiary` | `#64748B` (slate-500) | Metadata, secondary labels, and timestamps |
| `--text-disabled` | `#94A3B8` (slate-400) | Placeholder text and disabled controls |

### 2.3 Semantic Enforcement Palette (WCAG AA Compliant)
| Action | Text Hex | Background Hex | Border Hex | Description |
|---|---|---|---|---|
| **BLOCK** | `#991B1B` (red-800) | `#FEF2F2` (red-50) | `#FECACA` (red-200) | Action halted by deterministic policy |
| **ALLOW** | `#166534` (emerald-800) | `#F0FDF4` (emerald-50) | `#BBF7D0` (emerald-200) | Action verified and permitted |
| **HITL** | `#92400E` (amber-800) | `#FFFBEB` (amber-50) | `#FDE68A` (amber-200) | Human approval required |
| **MONITOR** | `#1E40AF` (blue-800) | `#EFF6FF` (blue-50) | `#BFDBFE` (blue-200) | Action allowed and audited |

### 2.4 Severity Palette
| Severity | Text Hex | Background Hex | Border Hex |
|---|---|---|---|
| **CRITICAL** | `#991B1B` | `#FEF2F2` | `#FECACA` |
| **HIGH** | `#9A3412` | `#FFF7ED` | `#FFEDD5` |
| **MEDIUM** | `#92400E` | `#FFFBEB` | `#FDE68A` |
| **LOW** | `#1E40AF` | `#EFF6FF` | `#BFDBFE` |
| **INFO** | `#334155` | `#F8FAFC` | `#E2E8F0` |

---

## 3. Typography & Monospace Rules

- **UI Font Family:** `Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`
- **Technical/Code Font Family:** `'IBM Plex Mono', 'Fira Code', ui-monospace, monospace`
- **Monospace Usage:** Strictly reserved for Context IDs (`ctx_005`), Trace IDs (`trc_ae604`), Agent IDs (`agt_orch001`), tool identifiers (`customer_db.read`), timestamps (`15:32:10`), and JSON/code snippets.

---

## 4. Layout & Information Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ ActShield Logo    Search agents, traces, incidents...   ● LOCAL   Tarun (Admin)│
├───────────────┬─────────────────────────────────────────────────────────────┤
│ OVERVIEW      │ Breadcrumbs / Page Context                                  │
│  Command Ctr  ├─────────────────────────────────────────────────────────────┤
│  Activity     │ Filter Bar [ Search... ] [ Source ▾ ] [ Taint ▾ ] [ Reset ] │
│ OPERATIONS    ├─────────────────────────────────────────────────────────────┤
│  Agents       │ High-Density Table                                          │
│  Tasks        │  ID      Source     Agent     Trust    Taint    Decision    │
│  Delegations  │  ctx001  User       Planner   Trusted  Clean    ALLOW       │
│  Access Matrix│  ctx005  Ext MCP    Orchestr  Untrust  Critical BLOCK       │
│ SECURITY      │                                                             │
│  Context      │                                                             │
│  Threat Model │                                                             │
│  Policies     │                                                             │
└───────────────┴─────────────────────────────────────────────────────────────┘
```

---

## 5. Component Library Standards

### 5.1 DataTable
- Standard padding: `9px 14px` per cell for optimal information density.
- Header: uppercase 10px bold text (`#64748B`) with bottom border (`#E2E8F0`).
- Row selection highlights the row with subtle blue tint (`#F0F9FF`) and triggers the right-side `DetailDrawer`.

### 5.2 DetailDrawer
- Fixed right-side panel (`480px` on desktop) with light gray background header (`#F8FAFC`).
- Contains the 4-Point Execution Truth card, Causal Provenance Lineage, Security Analysis, and raw payload viewer.

### 5.3 ExecutionTruth Pipeline
- Visual step progression displaying 4 discrete states:
  1. `INTENDED` (Yes / No)
  2. `REQUESTED` (Yes / No)
  3. `ALLOWED` (Yes / No)
  4. `EXECUTED` (Yes / No)
- Clearly indicates the exact policy gate where execution was halted.
