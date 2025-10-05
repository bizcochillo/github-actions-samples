FROM registry.access.redhat.com/ubi9/ubi

ARG TARGET_PLATFORM
ARG RUNNER_VERSION=2.328.0
ARG RUNNER_CONTAINER_HOOKS_VERSION=0.7.0

# The UID env var should be used in child Containerfile.
ENV UID=1000
ENV GID=0
ENV USERNAME="runner"

# This is to mimic the OpenShift behaviour of adding the dynamic user to group 0.
RUN useradd -G 0 $USERNAME
ENV HOME /home/${USERNAME}

# Make and set the working directory
RUN mkdir -p /home/runner \
    && chown -R $USERNAME:$GID /home/runner
WORKDIR /home/runner

# Runner download supports amd64 as x64
RUN export ARCH=$(echo ${TARGET_PLATFORM} | cut -d / -f2) \
    && if [ "$ARCH" = "x86_64" ]; then export ARCH=x64 ; fi \
    && echo RUNNER_URL_ADDRESS=https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-${ARCH}-${RUNNER_VERSION}.tar.gz \
    && curl -L -o runner.tar.gz https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-${ARCH}-${RUNNER_VERSION}.tar.gz \
    && tar xzf ./runner.tar.gz \
    && rm runner.tar.gz \
    && ./bin/installdependencies.sh \
    && dnf clean all

# Software installation
RUN dnf install -y \
        unzip \
        golang \
        git \
        jq \
        https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
RUN dnf install -y \
        stress --nogpgcheck

# Install helm using the in-line curl to bash method
RUN curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Use an install script to install the `gh` cli, more about that below!
COPY images/software/gh-cli.sh gh-cli.sh
RUN yum-config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
RUN yum install -y gh

RUN if [ "$TARGET_PLATFORM" = "arm64" ]; then export ARCH_AWS=aarch64; else export ARCH_AWS=x86_64 ; fi \    
    && curl https://awscli.amazonaws.com/awscli-exe-linux-${ARCH_AWS}.zip -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install

RUN echo "--- Installing OC and KubeCTL CLI (Multi-Arch) ---" \    
    && OC_ARCH_FILE="openshift-client-linux.tar.gz" \
    && if [ "$TARGET_PLATFORM" = "arm64" ]; then OC_ARCH_FILE="openshift-client-linux-arm64.tar.gz"; fi \
    && curl -LO https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable/$OC_ARCH_FILE \
    && tar -xzf $OC_ARCH_FILE \
    && mv oc kubectl /usr/local/bin/ \
    && rm -f $OC_ARCH_FILE README.md

RUN echo "--- Final Cleanup and Lock Down ---" \
    && dnf clean all \
    && rm -f /usr/bin/dnf /usr/bin/yum \
    && rm -rf /var/cache/dnf /var/cache/yum