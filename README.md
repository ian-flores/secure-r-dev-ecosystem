# secure-r-dev ecosystem

[![CI](https://github.com/ian-flores/secure-r-dev-ecosystem/actions/workflows/ci.yml/badge.svg)](https://github.com/ian-flores/secure-r-dev-ecosystem/actions/workflows/ci.yml)
[![Tutorial](https://img.shields.io/badge/tutorial-Building%20a%20Data%20Analyst%20Agent-blue)](https://ian-flores.github.io/secure-r-dev-ecosystem/)

Cross-package integration tests and flagship tutorial for the **secure-r-dev** stack: seven R packages for building governed AI agents with sandboxed execution, guardrails, RAG context, graph orchestration, observability, and benchmarking. Each package lives in its own repository under the `ian-flores` GitHub org; this repo wires them all together.

## Architecture

```
                     ┌─────────────┐
                     │   securer    │  Sandboxed R execution + tool-call IPC
                     └──────┬───────┘
           ┌────────────────┼────────────────┐
           │                │                │
    ┌──────▼──────┐  ┌─────▼──────┐  ┌──────▼─────────┐
    │ securetools  │  │secureguard │  │ securecontext   │
    │  (tools)     │  │ (guards)   │  │ (memory / RAG)  │
    └──────┬───────┘  └─────┬──────┘  └──────┬──────────┘
           └────────────────┼────────────────┘
                     ┌──────▼───────┐
                     │   orchestr    │  Graph-based agent orchestration
                     └──────┬───────┘
           ┌────────────────┼────────────────┐
           │                                 │
    ┌──────▼──────┐                   ┌──────▼──────┐
    │ securetrace  │                  │ securebench  │
    │(observability)│                 │ (benchmarks) │
    └──────────────┘                  └──────────────┘
```

## Packages

| Package | Description | Repo |
|---------|-------------|------|
| **securer** | Sandboxed R execution, tool-call IPC, Seatbelt/bwrap isolation | [ian-flores/securer](https://github.com/ian-flores/securer) |
| **securetools** | Pre-built security-hardened tools (calculator, file I/O, SQL, plotting) | [ian-flores/securetools](https://github.com/ian-flores/securetools) |
| **secureguard** | Input/code/output guardrails: prompt injection, AST analysis, PII/secret detection | [ian-flores/secureguard](https://github.com/ian-flores/secureguard) |
| **orchestr** | Graph-based agent workflows: ReAct, pipelines, supervisor routing | [ian-flores/orchestr](https://github.com/ian-flores/orchestr) |
| **securecontext** | Document chunking, TF-IDF embeddings, vector search, knowledge store | [ian-flores/securecontext](https://github.com/ian-flores/securecontext) |
| **securetrace** | Structured tracing, spans, token/cost accounting, JSONL/Prometheus export | [ian-flores/securetrace](https://github.com/ian-flores/securetrace) |
| **securebench** | Guardrail benchmarking, precision/recall/F1 metrics | [ian-flores/securebench](https://github.com/ian-flores/securebench) |

## Quick start

Install all seven packages from GitHub:

```r
pak::pak(paste0("ian-flores/", c(
  "securer", "securetools", "secureguard", "securecontext",
  "orchestr", "securetrace", "securebench"
)))
```

Clone this repo and run the integration tests:

```r
testthat::test_dir("tests/testthat")
```

## What's in this repo

| Path | Description |
|------|-------------|
| `tests/testthat/test-integration-pipeline.R` | 32 tests across 7 layers, 141 assertions, exercises all packages through a "data analyst agent" scenario |
| `vignettes/governed-agent-walkthrough.Rmd` | "Building a Data Analyst Agent" tutorial -- runs without API keys |
| `tests/run-integration.R` | Installs packages and runs the full test suite |

The rendered tutorial is published at **<https://ian-flores.github.io/secure-r-dev-ecosystem/>**.

## Test layers

| Layer | Packages | Tests |
|-------|----------|-------|
| 1. Foundation | securer + securetools | Session with tools, session pool, Docker sandbox |
| 2. Guardrails | secureguard | Pipeline, pre-execute hooks, secret detection, composition |
| 3. Context | securecontext | RAG round-trip, encrypted knowledge store, context builder |
| 4. Orchestration | orchestr | Graph building, state passing, streaming, memory |
| 5. Tracing | securetrace | Spans, exporters, log correlation, cost accounting |
| 6. Evaluation | securebench | Benchmarking, guard comparison |
| 7. Full Pipeline | All 7 packages | End-to-end governed agent workflow |

All tests use `skip_if_not_installed()` for graceful degradation. No external API keys are required.

## License

MIT. Each individual package carries its own license in its respective repository.
