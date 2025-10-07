FROM registry.access.redhat.com/ubi9/ubi

ARG TARGET_PLATFORM
ARG RUNNER_VERSION=2.328.0
ARG RUNNER_CONTAINER_HOOKS_VERSION=0.7.0

# Shell setup for robustness
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# 1. User/Group Setup (Least Frequent Change - Early for Caching)
# The UID env var should be used in child Containerfile.
ENV UID=1001
ENV GID=123
ENV USERNAME="runner"

# Create user/group and set HOME
# The dynamic user is added to group 0 to mimic OpenShift behavior.
RUN set -euxo pipefail \
    && groupadd -g ${GID} docker \
    && useradd -u ${UID} -g ${GID} -G 0 -m -d /home/${USERNAME} -s /bin/bash ${USERNAME}
ENV HOME /home/${USERNAME}

# Set up the runner directory and permissions
RUN set -euxo pipefail \
    && mkdir -p /home/runner \
    && chown -R $USERNAME:$GID /home/runner
WORKDIR /home/runner

# 2. Package Installation (Combined and Cleaned Up)
# Combine all package installations and run dnf clean all only once.
# Install EPEL first, then other packages.
RUN set -euxo pipefail \
    && dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm \
    # Install core packages
    && dnf install -y \
        unzip \
        golang \
        git \
        jq \
        stress \
        dnf-utils \
        gh \
        --nogpgcheck \
    # Install gh cli repo config, then install gh
    # Note: I am assuming the EPEL-release above is for ubi9/rhel9,
    # so I updated the EPEL URL to use the latest-9 link.
    # UBI9 uses `dnf` for everything, not `yum`.
    && dnf config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo \
    && dnf install -y gh

# 3. Runner Download (Self-contained and Cleaned Up)
# Use a single RUN layer for download, extraction, dependency install, and cleanup.
RUN set -euxo pipefail \
    && export ARCH=$(echo ${TARGET_PLATFORM} | cut -d / -f2) \
    && if [ "$ARCH" = "x86_64" ]; then export ARCH=x64 ; fi \
    && RUNNER_URL_ADDRESS="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-${ARCH}-${RUNNER_VERSION}.tar.gz" \
    && echo "Downloading Runner from: $RUNNER_URL_ADDRESS" \
    && curl -L -o runner.tar.gz $RUNNER_URL_ADDRESS \
    && tar xzf ./runner.tar.gz \
    && rm runner.tar.gz \
    && ./bin/installdependencies.sh

# 4. Helm Installation (Self-contained and Cleaned Up)
RUN set -euxo pipefail \
    && curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# 5. AWS CLI Installation (Self-contained and Cleaned Up)
RUN set -euxo pipefail \
    && if [ "$TARGET_PLATFORM" = "arm64" ]; then export ARCH_AWS=aarch64; else export ARCH_AWS=x86_64 ; fi \
    && AWS_URL="https://awscli.amazonaws.com/awscli-exe-linux-${ARCH_AWS}.zip" \
    && echo "Downloading AWS CLI from: $AWS_URL" \
    && curl $AWS_URL -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf awscliv2.zip ./aws

# 6. OC/KubeCTL Installation (Self-contained and Cleaned Up)
RUN set -euxo pipefail \
    && echo "--- Installing OC and KubeCTL CLI (Multi-Arch) ---" \
    && OC_ARCH_FILE="openshift-client-linux.tar.gz" \
    && if [ "$TARGET_PLATFORM" = "arm64" ]; then OC_ARCH_FILE="openshift-client-linux-arm64.tar.gz"; fi \
    && curl -LO https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable/$OC_ARCH_FILE \
    && tar -xzf $OC_ARCH_FILE \
    && mv oc kubectl /usr/local/bin/ \
    && rm -f $OC_ARCH_FILE README.md

# 7. Final Cleanup and Lockdown
# This is a critical final step to ensure minimum image size.
RUN set -euxo pipefail \
    && echo "--- Final Cleanup and Lock Down ---" \
    && dnf clean all \
    && rm -f /usr/bin/dnf /usr/bin/yum \
    && rm -rf /var/cache/dnf /var/cache/yum