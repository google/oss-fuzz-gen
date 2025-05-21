# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Build a virtualenv using the appropriate Debian release:
# * Install python3-venv for the built-in Python3 venv module (not installed by default).
# * Install gcloud CLI from Google Cloud's apt repository.

# Stage 1: Build
FROM debian:12 AS build

RUN apt-get update && apt-get install --no-install-recommends -y \
    python3 \
    python3-venv \
    python3-pip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /venv

COPY requirements.txt /tmp/
RUN /venv/bin/pip install --disable-pip-version-check -r /tmp/requirements.txt && \
    rm -rf /root/.cache/pip


#Stage 2: Runtime
FROM debian:12
# Set timezone to Australia/Sydney.

ENV TZ='Australia/Sydney'
SHELL ["/bin/bash", "-c"]

# Install packages used by the Experiment. Python and Git are required for the experiment.
# Curl, certs, and gnupg are required to install gcloud.
RUN apt-get update && apt-get install --no-install-recommends -y \
    python3 \
    python3-venv \
    gcc \
    libpython3-dev \
    git \
    apt-transport-https \
    ca-certificates \
    gnupg \
    curl \
    wget2 \
    clang-format \
    lsb-release && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install gcloud cli.
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /etc/apt/keyrings/cloud.google.gpg && \
    chmod a+r /etc/apt/keyrings/cloud.google.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | \
    tee /etc/apt/sources.list.d/google-cloud-sdk.list && \
    apt-get update -y && \
    apt-get install --no-install-recommends -y google-cloud-cli && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Docker for OSS-Fuzz.
# Add Docker's official GPG key:
# Add the repository to Apt sources:
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    chmod a+r /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get install --no-install-recommends -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY . /experiment
WORKDIR /experiment

COPY --from=build /venv /venv

ENTRYPOINT ["/venv/bin/python3", "./report/docker_run.py"]
