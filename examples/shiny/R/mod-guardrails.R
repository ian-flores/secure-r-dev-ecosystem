# Guardrails Module
#
# Displays guardrail check results as pass/fail badges.

guardrails_ui <- function(id) {
  ns <- NS(id)
  wellPanel(
    h4("Guardrail Results"),
    uiOutput(ns("badges"))
  )
}

guardrails_server <- function(id, guardrail_results) {
  moduleServer(id, function(input, output, session) {

    output$badges <- renderUI({
      results <- guardrail_results()

      if (length(results) == 0) {
        return(div(
          style = "color: #999; padding: 10px;",
          "No guardrail checks yet. Send a message to see results."
        ))
      }

      make_badge <- function(label, result) {
        if (is.na(result$pass)) {
          span(class = "badge-pending", paste(label, ": skipped"))
        } else if (result$pass) {
          span(class = "badge-pass", paste(label, ": PASS"))
        } else {
          reasons <- if (!is.null(result$reasons)) {
            paste(result$reasons, collapse = "; ")
          } else {
            "blocked"
          }
          tagList(
            span(class = "badge-fail", paste(label, ": FAIL")),
            tags$small(style = "color: #c62828; margin-left: 8px;", reasons)
          )
        }
      }

      warnings_ui <- NULL
      all_warnings <- c(
        results$input$warnings %||% character(0),
        results$output$warnings %||% character(0)
      )
      if (length(all_warnings) > 0) {
        warnings_ui <- div(
          style = "margin-top: 8px; padding: 6px; background: #fff3e0;
                   border-radius: 4px; font-size: 12px;",
          tags$strong("Warnings: "),
          paste(all_warnings, collapse = "; ")
        )
      }

      tagList(
        div(style = "display: flex; gap: 12px; flex-wrap: wrap; padding: 8px;",
          div(make_badge("Input", results$input)),
          div(make_badge("Code", results$code)),
          div(make_badge("Output", results$output))
        ),
        warnings_ui
      )
    })
  })
}
