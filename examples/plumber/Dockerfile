# Plumber API for governed agent
# Based on the production image which has all 7 packages installed

FROM ghcr.io/ian-flores/secure-r-dev/production:latest AS base

# Switch to root to install plumber
USER root
RUN Rscript -e "install.packages('plumber', repos = 'https://cloud.r-project.org')"

# Copy API files
COPY examples/plumber/plumber.R /app/plumber.R
COPY examples/plumber/entrypoint.R /app/entrypoint.R

# Switch back to non-root user
USER ruser
WORKDIR /app

EXPOSE 8000

CMD ["Rscript", "entrypoint.R"]
