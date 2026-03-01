#!/usr/bin/env Rscript
# Install all 7 ecosystem packages in dependency order
# Usage: Rscript ecosystem/tests/install-all.R

# ecosystem/tests/ -> ecosystem/ -> root (where packages live)
root <- normalizePath(file.path(dirname(sys.frame(1)$ofile), "..", ".."))

pkgs <- c(
  "securer",
  "securetools",
  "secureguard",
  "securecontext",
  "orchestr",
  "securetrace",
  "securebench"
)

for (pkg in pkgs) {
  pkg_dir <- file.path(root, pkg)
  if (!dir.exists(pkg_dir)) {
    stop("Package directory not found: ", pkg_dir)
  }
  message("Installing ", pkg, " from ", pkg_dir)
  devtools::install(pkg_dir, dependencies = FALSE, upgrade = "never", quiet = TRUE)
  message("  OK: ", pkg, " ", as.character(packageVersion(pkg)))
}

message("\nAll 7 packages installed successfully.")
