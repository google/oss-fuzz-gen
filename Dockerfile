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
# Set timezone to Australia/Sydney.
ENV TZ='Australia/Sydney'


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

# Prepare local fuzz introspector.
RUN apt install -y python3-virtualenv && \
    clone https://github.com/ossf/fuzz-introspector /fi && \
    cd /fi/tools/web-fuzzing-introspection && \
    python3 -m virtualenv .venv && \
    .venv/bin/pip install -r ./requirements.txt


ENTRYPOINT ["./report/docker_run.sh"]
