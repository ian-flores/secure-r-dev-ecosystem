# Traces Module
#
# Displays trace spans with timing information.

traces_ui <- function(id) {
  ns <- NS(id)
  wellPanel(
    h4("Trace Timeline"),
    uiOutput(ns("timeline"))
  )
}

traces_server <- function(id, trace_data) {
  moduleServer(id, function(input, output, session) {

    output$timeline <- renderUI({
      tr <- trace_data()

      if (length(tr) == 0) {
        return(div(
          style = "color: #999; padding: 10px;",
          "No traces yet. Send a message to generate a trace."
        ))
      }

      # Trace header
      status_color <- switch(tr$status,
        completed = "#28a745",
        error = "#dc3545",
        "#ffc107"
      )
      duration_str <- if (!is.null(tr$duration_secs)) {
        sprintf("%.3fs", tr$duration_secs)
      } else {
        "N/A"
      }

      header <- div(
        style = "padding: 6px 0; border-bottom: 2px solid #333; margin-bottom: 6px;",
        tags$strong(tr$name),
        span(
          style = sprintf("color: %s; margin-left: 10px;", status_color),
          tr$status
        ),
        span(class = "span-duration", duration_str),
        div(
          style = "font-size: 11px; color: #999;",
          paste("Trace ID:", substr(tr$trace_id, 1, 16), "...")
        )
      )

      # Span rows
      span_rows <- lapply(tr$spans, function(s) {
        type_color <- switch(s$type,
          llm = "#1976d2",
          guardrail = "#7b1fa2",
          tool = "#388e3c",
          "#666"
        )
        status_icon <- switch(s$status,
          ok = "\u2713",
          error = "\u2717",
          completed = "\u2713",
          "\u2022"
        )
        status_color_span <- switch(s$status,
          ok = "#28a745",
          completed = "#28a745",
          error = "#dc3545",
          "#ffc107"
        )
        dur <- if (!is.null(s$duration_secs)) {
          sprintf("%.3fs", s$duration_secs)
        } else {
          ""
        }

        tokens_str <- ""
        if (!is.null(s$input_tokens) && s$input_tokens > 0) {
          tokens_str <- sprintf(" | %d in / %d out tokens",
                                 s$input_tokens, s$output_tokens %||% 0)
        }

        div(class = "span-row",
          span(class = "span-type",
               style = sprintf("color: %s;", type_color),
               s$type),
          span(style = sprintf("color: %s; margin-right: 6px;", status_color_span),
               status_icon),
          s$name,
          tags$small(style = "color: #999;", tokens_str),
          span(class = "span-duration", dur)
        )
      })

      tagList(header, span_rows)
    })
  })
}
