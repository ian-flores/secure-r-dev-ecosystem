# Governed Agent Plumber API
#
# Endpoints:
#   POST /chat       -- Governed agent endpoint with guardrail checks
#   GET  /trace/:id  -- Retrieve trace by ID
#   POST /guardrail  -- Run guardrail check on text
#   GET  /health     -- Package healthcheck
#   GET  /metrics    -- Prometheus-format metrics

library(securer)
library(securetools)
library(secureguard)
library(securecontext)
library(securetrace)

# --- Shared state -----------------------------------------------------------

# Guardrail pipeline
guardrail_pipeline <- secure_pipeline(
  input_guardrails = list(
    guard_prompt_injection(),
    guard_input_pii()
  ),
  code_guardrails = list(
    guard_code_analysis(),
    guard_code_complexity(max_ast_depth = 20)
  ),
  output_guardrails = list(
    guard_output_pii(action = "redact"),
    guard_output_secrets(action = "redact")
  )
)

# Trace storage (in-memory for demo; production would use a database)
trace_store <- new.env(parent = emptyenv())
trace_store$traces <- list()
trace_store$guardrail_checks <- 0L
trace_store$guardrail_passes <- 0L
trace_store$guardrail_blocks <- 0L

# Prometheus registry
prom_registry <- prometheus_registry()

# Session pool for sandboxed execution
session_pool <- SecureSessionPool$new(size = 2, sandbox = FALSE)

# Register tools
calc_tool <- calculator_tool()
session_pool$register_tool(calc_tool)

# --- Helpers -----------------------------------------------------------------

store_trace <- function(trace) {
  trace_list <- trace$to_list()
  trace_store$traces[[trace_list$trace_id]] <- trace_list
  prometheus_metrics(trace, prom_registry)
  invisible(trace_list$trace_id)
}

# Mock LLM response (no external API required)
mock_llm_response <- function(message) {
  responses <- list(
    default = "I can help you with R programming. Could you be more specific?",
    math = "I can calculate that for you using R's built-in math functions.",
    data = "For data analysis, I recommend using dplyr and ggplot2.",
    help = "I'm a governed AI assistant for R programming questions."
  )

  msg_lower <- tolower(message)
  if (grepl("calculat|math|\\d+", msg_lower)) {
    responses$math
  } else if (grepl("data|analysis|csv", msg_lower)) {
    responses$data
  } else if (grepl("help|who|what are", msg_lower)) {
    responses$help
  } else {
    responses$default
  }
}

# --- Endpoints ---------------------------------------------------------------

#* Health check -- loads all packages and reports status
#* @get /health
#* @serializer json
function() {
  packages <- c("securer", "securetools", "secureguard",
                "securecontext", "securetrace")
  status <- vapply(packages, function(pkg) {
    tryCatch({
      requireNamespace(pkg, quietly = TRUE)
      "ok"
    }, error = function(e) "error")
  }, character(1))

  list(
    status = if (all(status == "ok")) "healthy" else "degraded",
    packages = as.list(status),
    timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ", tz = "UTC"),
    pool_size = 2L
  )
}

#* Governed agent chat endpoint
#* @post /chat
#* @param message:character The user message
#* @serializer json
function(req, message = "") {
  if (!nzchar(message)) {
    res$status <- 400L
    return(list(error = "message parameter is required"))
  }

  tr <- Trace$new("chat-request", metadata = list(endpoint = "/chat"))
  tr$start()

  # Input guardrail check
  input_span <- Span$new("input-guardrail", type = "guardrail")
  input_span$start()
  input_check <- guardrail_pipeline$check_input(message)
  trace_store$guardrail_checks <- trace_store$guardrail_checks + 1L
  input_span$end(status = if (input_check$pass) "ok" else "error")
  tr$add_span(input_span)

  if (!input_check$pass) {
    trace_store$guardrail_blocks <- trace_store$guardrail_blocks + 1L
    tr$status <- "error"
    tr$end()
    store_trace(tr)
    return(list(
      blocked = TRUE,
      reasons = input_check$reasons,
      trace_id = tr$trace_id
    ))
  }
  trace_store$guardrail_passes <- trace_store$guardrail_passes + 1L

  # LLM call (mocked)
  llm_span <- Span$new("llm-call", type = "llm")
  llm_span$start()
  llm_span$set_model("mock-gpt-4o")
  llm_span$set_tokens(input = nchar(message), output = 50L)
  response <- mock_llm_response(message)
  llm_span$end()
  tr$add_span(llm_span)

  # Output guardrail check
  output_span <- Span$new("output-guardrail", type = "guardrail")
  output_span$start()
  output_check <- guardrail_pipeline$check_output(response)
  trace_store$guardrail_checks <- trace_store$guardrail_checks + 1L
  if (output_check$pass) {
    trace_store$guardrail_passes <- trace_store$guardrail_passes + 1L
  } else {
    trace_store$guardrail_blocks <- trace_store$guardrail_blocks + 1L
  }
  output_span$end(status = "ok")
  tr$add_span(output_span)

  tr$end()
  trace_id <- store_trace(tr)

  list(
    response = output_check$result,
    blocked = FALSE,
    guardrails = list(
      input_pass = input_check$pass,
      output_pass = output_check$pass,
      warnings = c(input_check$warnings, output_check$warnings)
    ),
    trace_id = trace_id
  )
}

#* Run guardrail check on text
#* @post /guardrail
#* @param text:character Text to check
#* @param type:character Guardrail type (input, code, output)
#* @serializer json
function(text = "", type = "input") {
  if (!nzchar(text)) {
    res$status <- 400L
    return(list(error = "text parameter is required"))
  }

  trace_store$guardrail_checks <- trace_store$guardrail_checks + 1L

  result <- switch(type,
    "input" = guardrail_pipeline$check_input(text),
    "code" = guardrail_pipeline$check_code(text),
    "output" = guardrail_pipeline$check_output(text),
    {
      res$status <- 400L
      return(list(error = "type must be one of: input, code, output"))
    }
  )

  if (result$pass) {
    trace_store$guardrail_passes <- trace_store$guardrail_passes + 1L
  } else {
    trace_store$guardrail_blocks <- trace_store$guardrail_blocks + 1L
  }

  list(
    pass = result$pass,
    type = type,
    warnings = result$warnings,
    reasons = if (!result$pass) result$reasons else list()
  )
}

#* Retrieve trace by ID
#* @get /trace/<id>
#* @param id:character Trace ID
#* @serializer json
function(id) {
  trace_data <- trace_store$traces[[id]]
  if (is.null(trace_data)) {
    res$status <- 404L
    return(list(error = paste("Trace not found:", id)))
  }
  trace_data
}

#* Prometheus-format metrics
#* @get /metrics
#* @serializer text
#* @contentType text/plain; version=0.0.4; charset=utf-8
function() {
  format_prometheus(prom_registry)
}
