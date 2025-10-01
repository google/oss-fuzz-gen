# Build a virtualenv using the appropriate Debian release:
# * Install python3-venv for the built-in Python3 venv module (not installed by default).
# * Install gcloud CLI from Google Cloud's apt repository.

FROM debian:12
# Install packages used by the Experiment. Python and Git are required for the experiment.
# Curl, certs, and gnupg are required to install gcloud.
RUN apt-get update && \
    apt-get install --no-install-suggests --no-install-recommends --yes \
    python3-venv \
    gcc \
    libpython3-dev \
    git \
    apt-transport-https \
    ca-certificates \
    gnupg \
    curl \
    wget2 \
    clang-format && \
    python3 -m venv /venv
# Install gcloud cli.
RUN echo "deb https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add - && \
    apt-get update -y && \
    apt-get install google-cloud-cli -y
# Set timezone to Singapore
ENV TZ='Asia/Singapore'

# Install Docker for OSS-Fuzz.
# Add Docker's official GPG key:
RUN apt-get install ca-certificates curl gnupg && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    chmod a+r /etc/apt/keyrings/docker.gpg
# Add the repository to Apt sources:
RUN echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null
RUN apt-get update && \
    apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

COPY . /experiment
WORKDIR /experiment
RUN /venv/bin/pip install --disable-pip-version-check -r requirements.txt
ENTRYPOINT ["/venv/bin/python3", "./report/docker_run.py"]
