#!/usr/bin/env Rscript
# Run cross-package integration tests for the secure-r-dev ecosystem.
#
# Usage:
#   Rscript ecosystem/tests/run-integration.R
#
# This script:
#   1. Installs all 7 packages in dependency order (via install-all.R)
#   2. Runs the integration test suite
#
# Tests use skip_if_not_installed() so they degrade gracefully if
# individual packages fail to install.

# ecosystem/tests/ -> ecosystem/ -> root
eco_dir <- normalizePath(file.path(dirname(sys.frame(1)$ofile), ".."))
root <- normalizePath(file.path(eco_dir, ".."))
setwd(root)

# --- Step 1: Install all packages ---
message("=== Installing all 7 ecosystem packages ===\n")
source(file.path(eco_dir, "tests", "install-all.R"))

# --- Step 2: Run integration tests ---
message("\n=== Running integration tests ===\n")
Sys.setenv(NOT_CRAN = "true")

results <- testthat::test_dir(
  file.path(eco_dir, "tests", "testthat"),
  reporter = "summary",
  stop_on_failure = FALSE
)

# --- Step 3: Report ---
n_fail <- sum(as.data.frame(results)$failed)
n_skip <- sum(as.data.frame(results)$skipped)
n_pass <- sum(as.data.frame(results)$passed)

message(sprintf(
  "\nResults: %d passed, %d failed, %d skipped",
  n_pass, n_fail, n_skip
))

if (n_fail > 0) {
  quit(status = 1)
}
