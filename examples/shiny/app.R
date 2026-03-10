# Governed Agent Dashboard
#
# 3-panel Shiny app:
#   - Chat panel (left) -- text input, send button, conversation display
#   - Guardrails panel (top-right) -- pass/fail badges for guardrail checks
#   - Traces panel (bottom-right) -- trace timeline visualization

library(shiny)
library(securer)
library(secureguard)
library(securetrace)

# Load modules
source("R/mod-chat.R")
source("R/mod-guardrails.R")
source("R/mod-traces.R")

# -- Shared state -------------------------------------------------------------

# Guardrail pipeline
guardrail_pipeline <- secure_pipeline(
  input_guardrails = list(
    guard_prompt_injection(),
    guard_input_pii()
  ),
  code_guardrails = list(
    guard_code_analysis()
  ),
  output_guardrails = list(
    guard_output_pii(action = "redact"),
    guard_output_secrets(action = "redact")
  )
)

# Mock LLM response
mock_respond <- function(message) {
  msg_lower <- tolower(message)
  if (grepl("calculat|math|\\d+", msg_lower)) {
    "I can calculate that for you using R's built-in math functions."
  } else if (grepl("data|analysis|csv", msg_lower)) {
    "For data analysis, I recommend using dplyr and ggplot2 in R."
  } else if (grepl("help|who|what are", msg_lower)) {
    "I'm a governed AI assistant for R programming questions."
  } else if (grepl("code|write|function", msg_lower)) {
    "Here's an example:\n```r\nmy_func <- function(x) x^2\nresult <- my_func(5)\nprint(result)\n```"
  } else {
    "I can help you with R programming. Could you be more specific?"
  }
}

# -- UI -----------------------------------------------------------------------

ui <- fluidPage(
  tags$head(
    tags$style(HTML("
      body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
      .badge-pass { background-color: #28a745; color: white; padding: 4px 8px;
                    border-radius: 4px; font-size: 12px; }
      .badge-fail { background-color: #dc3545; color: white; padding: 4px 8px;
                    border-radius: 4px; font-size: 12px; }
      .badge-pending { background-color: #6c757d; color: white; padding: 4px 8px;
                       border-radius: 4px; font-size: 12px; }
      .chat-message { padding: 8px 12px; margin: 4px 0; border-radius: 8px; }
      .chat-user { background-color: #e3f2fd; text-align: right; }
      .chat-assistant { background-color: #f5f5f5; }
      .chat-blocked { background-color: #ffebee; color: #c62828; }
      .span-row { padding: 4px 0; border-bottom: 1px solid #eee; font-size: 13px; }
      .span-type { display: inline-block; width: 70px; font-weight: bold; }
      .span-duration { color: #666; float: right; }
      h4 { margin-top: 10px; }
    "))
  ),

  titlePanel("Governed Agent Dashboard"),

  fluidRow(
    # Left panel: Chat
    column(5,
      chat_ui("chat")
    ),

    # Right panel: Guardrails + Traces
    column(7,
      fluidRow(
        column(12, guardrails_ui("guardrails"))
      ),
      fluidRow(
        column(12, traces_ui("traces"))
      )
    )
  )
)

# -- Server -------------------------------------------------------------------

server <- function(input, output, session) {

  # Reactive values for cross-module communication
  guardrail_results <- reactiveVal(list())
  trace_data <- reactiveVal(list())

  # Chat module -- returns list with response info
  chat_result <- chat_server("chat", function(message) {
    # Create trace
    tr <- Trace$new("chat-request")
    tr$start()

    # Input guardrail
    input_span <- Span$new("input-guardrail", type = "guardrail")
    input_span$start()
    input_check <- guardrail_pipeline$check_input(message)
    input_span$end(status = if (input_check$pass) "ok" else "error")
    tr$add_span(input_span)

    if (!input_check$pass) {
      tr$status <- "error"
      tr$end()
      guardrail_results(list(
        input = list(pass = FALSE, reasons = input_check$reasons),
        output = list(pass = NA),
        code = list(pass = NA)
      ))
      trace_data(tr$to_list())
      return(list(
        blocked = TRUE,
        response = paste("Blocked:", paste(input_check$reasons, collapse = "; ")),
        trace_id = tr$trace_id
      ))
    }

    # LLM call (mocked)
    llm_span <- Span$new("llm-call", type = "llm")
    llm_span$start()
    llm_span$set_model("mock-gpt-4o")
    llm_span$set_tokens(input = as.integer(nchar(message)), output = 50L)
    response <- mock_respond(message)
    llm_span$end()
    tr$add_span(llm_span)

    # Output guardrail
    output_span <- Span$new("output-guardrail", type = "guardrail")
    output_span$start()
    output_check <- guardrail_pipeline$check_output(response)
    output_span$end(status = "ok")
    tr$add_span(output_span)

    tr$end()

    # Update shared state
    guardrail_results(list(
      input = list(pass = input_check$pass, warnings = input_check$warnings),
      output = list(pass = output_check$pass, warnings = output_check$warnings),
      code = list(pass = NA)
    ))
    trace_data(tr$to_list())

    list(
      blocked = FALSE,
      response = output_check$result,
      trace_id = tr$trace_id
    )
  })

  # Guardrails module
  guardrails_server("guardrails", guardrail_results)

  # Traces module
  traces_server("traces", trace_data)
}

shinyApp(ui, server)
