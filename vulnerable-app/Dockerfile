# Using outdated base image
FROM python:3.8

# Running as root (security issue)
WORKDIR /app

# Copying everything including secrets
COPY . .

# Installing unnecessary packages
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    vim \
    net-tools \
    telnet \
    && pip install -r requirements.txt

# Exposing unnecessary port
EXPOSE 5000 22

# No healthcheck
# Running as root user
CMD ["python", "app.py"]