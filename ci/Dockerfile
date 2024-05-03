FROM debian:12

ENV DEBIAN_FRONTEND interactive

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
    apt-get install google-cloud-cli kubectl -y

COPY ci /opt/oss-fuzz-gen
RUN /venv/bin/pip install -r /opt/oss-fuzz-gen/requirements.txt

ENTRYPOINT ["/venv/bin/python3", "/opt/oss-fuzz-gen/ci_trial_build.py"]
