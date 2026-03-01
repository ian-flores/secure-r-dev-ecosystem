# Run cross-package integration tests
# Assumes all 7 packages are installed (run tests/install-all.R first)
library(testthat)

# These are not CRAN tests, so disable skip_on_cran()
Sys.setenv(NOT_CRAN = "true")

test_dir(
  "testthat",
  reporter = "summary",
  stop_on_failure = TRUE
)
