# Copyright 2025 Google LLC
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
FROM debian:12

ENV DEBIAN_FRONTEND interactive

# Set the same timezone as the main Dockerfile
ENV TZ='Australia/Sydney'

# Install packages used by the Experiment. Python and Git are required for the experiment.
# Curl, certs, and gnupg are required to install gcloud.
RUN apt-get update && \
    apt-get install --no-install-suggests --no-install-recommends --yes \
    python3-pip \
    python3-venv \
    git \
    apt-transport-https \
    ca-certificates \
    gnupg \
    curl

RUN python3 -m venv /venv

# Install gcloud cli.
RUN echo "deb https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add - && \
    apt-get update -y && \
    apt-get install google-cloud-cli kubectl google-cloud-sdk-gke-gcloud-auth-plugin -y

COPY ci /opt/oss-fuzz-gen
RUN /venv/bin/pip install -r /opt/oss-fuzz-gen/requirements.txt

ENTRYPOINT ["/venv/bin/python3", "/opt/oss-fuzz-gen/ci_trial_build.py"]
