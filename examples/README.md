# secure-r-dev Examples

End-to-end examples demonstrating the 7-package governed AI agent stack for R.

## Contents

### [Governed Agent Walkthrough](vignettes/governed-agent-walkthrough.Rmd)

Full narrative Rmd covering all 7 packages: sandboxed execution, tools, guardrails, RAG context, graph orchestration, tracing, and benchmarking. Runs without external API keys.

### [Plumber API](plumber/)

REST API exposing a governed agent with endpoints for chat, guardrail checking, trace retrieval, health, and Prometheus metrics.

- `POST /chat` -- Governed agent endpoint with guardrail checks
- `GET /trace/{id}` -- Retrieve trace by ID
- `POST /guardrail` -- Run guardrail check on text
- `GET /health` -- Package healthcheck
- `GET /metrics` -- Prometheus-format metrics

### [Shiny App](shiny/)

Interactive 3-panel dashboard:

- **Chat panel** -- Send messages through a governed agent
- **Guardrails panel** -- Real-time pass/fail badges for input, code, and output guards
- **Traces panel** -- Timeline visualization of trace spans and timing

### [Docker Compose](docker-compose.yml)

Orchestrates the full stack: Plumber API + Shiny app + Jaeger (tracing UI) + Prometheus (metrics).

```bash
docker compose up --build
```

| Service     | URL                        |
|-------------|----------------------------|
| Plumber API | http://localhost:8000       |
| Shiny App   | http://localhost:3838       |
| Jaeger UI   | http://localhost:16686      |
| Prometheus  | http://localhost:9090       |
| Grafana     | http://localhost:3000       |

### [Grafana Dashboard](grafana/)

Pre-built Grafana dashboard for securetrace metrics. Auto-provisioned with Prometheus datasource.

Panels include:
- Total traces, spans, tokens, and cost (stat panels)
- Spans by type and status (pie charts)
- Span duration percentiles (time series)
- Token usage by model and direction
- Cost breakdown by model
- Guardrail health (pass/fail rates)

Login: admin / securetrace (or view anonymously)

### [Standalone Demo](demo-tracing.R)

Run the full traced workflow locally without Docker:

```r
Rscript examples/demo-tracing.R
```

Shows automatic span emission from secureguard, securetools, securer, securecontext, and securebench -- all captured by securetrace.

## Requirements

All examples run without external API keys. Where LLM calls would normally be needed, mock chat objects return canned responses.

To install all packages locally:

```r
for (pkg in c("securer", "securetools", "secureguard", "securecontext",
              "orchestr", "securetrace", "securebench")) {
  devtools::install(file.path("..", pkg))
}
```
