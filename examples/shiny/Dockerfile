# Shiny app for governed agent dashboard
# Based on the production image which has all 7 packages installed

FROM ghcr.io/ian-flores/secure-r-dev/production:latest AS base

# Switch to root to install shiny
USER root
RUN Rscript -e "install.packages('shiny', repos = 'https://cloud.r-project.org')"

# Copy app files
COPY examples/shiny/app.R /app/app.R
COPY examples/shiny/R/ /app/R/

# Switch back to non-root user
USER ruser
WORKDIR /app

EXPOSE 3838

CMD ["Rscript", "-e", "shiny::runApp('.', port = 3838, host = '0.0.0.0')"]
