# Chat Module
#
# Text input, send button, and conversation display panel.

chat_ui <- function(id) {
  ns <- NS(id)
  wellPanel(
    h4("Chat"),
    div(
      id = ns("conversation"),
      style = "height: 400px; overflow-y: auto; border: 1px solid #ddd;
               border-radius: 4px; padding: 8px; margin-bottom: 10px;
               background: white;",
      uiOutput(ns("messages"))
    ),
    fluidRow(
      column(10,
        textInput(ns("user_input"), NULL,
                  placeholder = "Type a message...",
                  width = "100%")
      ),
      column(2,
        actionButton(ns("send"), "Send",
                     class = "btn-primary",
                     style = "width: 100%; margin-top: 0;")
      )
    )
  )
}

chat_server <- function(id, process_message) {
  moduleServer(id, function(input, output, session) {

    # Conversation history
    messages <- reactiveVal(list())
    last_result <- reactiveVal(NULL)

    observeEvent(input$send, {
      req(nchar(trimws(input$user_input)) > 0)

      user_msg <- trimws(input$user_input)

      # Add user message
      msgs <- messages()
      msgs <- c(msgs, list(list(role = "user", text = user_msg)))

      # Process through governed agent
      result <- process_message(user_msg)

      # Add response
      if (result$blocked) {
        msgs <- c(msgs, list(list(role = "blocked", text = result$response)))
      } else {
        msgs <- c(msgs, list(list(role = "assistant", text = result$response)))
      }

      messages(msgs)
      last_result(result)

      # Clear input
      updateTextInput(session, "user_input", value = "")
    })

    output$messages <- renderUI({
      msgs <- messages()
      if (length(msgs) == 0) {
        return(div(
          style = "color: #999; text-align: center; padding: 20px;",
          "Send a message to start a conversation."
        ))
      }

      tagList(lapply(msgs, function(msg) {
        css_class <- switch(msg$role,
          user = "chat-message chat-user",
          assistant = "chat-message chat-assistant",
          blocked = "chat-message chat-blocked"
        )
        div(class = css_class, msg$text)
      }))
    })

    last_result
  })
}
