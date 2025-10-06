# Introduction
This article details the secure and robust deployment of the GitHub Actions Runner Controller (ARC) on Red Hat OpenShift Service on AWS (ROSA) from a very simple set of examples. We move beyond a basic installation to demonstrate several critical enterprise configurations, utilizing a sequence of targeted runner scale sets (SS) to showcase specific capabilities. The core scenarios covered are:

- **Secure Execution** (Runners Scale Set _ss-restricted_): Implementing a dedicated, restrictive OpenShift Security Context Constraint (github-arc) as a security "smoke test" to ensure runners operate with minimal privileges.

- **Cloud Credential Security** (_ss-irsa_): Integrating runners with AWS IAM Roles for Service Accounts (IRSA) to enable secure, short-lived token access to AWS resources, exemplified by accessing an AWS Secrets Manager item.

- **Capacity Planning** (_ss-request_): Configuring resource requests and limits to establish a guaranteed Quality of Service (QoS) for calculating optimal cluster scaling and meeting customer capacity needs. 

- **Multi-Architecture Support** (_ss-arm_): Deploying runners specifically targeting ARM-based Graviton instances for cost efficiency and workload performance.

- **Observability**: Enabling Prometheus metrics support within ARC and configuring the necessary OpenShift objects to integrate with the built-in User-Workload Monitoring instance.

> **NOTE:** Before executing any of the commands or configurations detailed in this guide, you must ensure two environment variables are set in your shell session: `GITHUB_CONFIG_URL` and `GITHUB_PAT`. These variables are necessary for the GitHub Actions Runner Controller to authenticate with your repository and register the self-hosted runners.
> ```bash
> export GITHUB_CONFIG_URL="https://github.com/bizcochillo/github-actions-samples"
> export GITHUB_PAT="<A PERSONAL ACCESS TOKEN HERE>"
> ```

# Install GitHub Actions Runner Controller (ARC)
We begin by installing the official GitHub Actions Runner Controller (ARC) using its Helm chart into the dedicated management namespace, `arc-systems`.
```bash
NAMESPACE="arc-systems"
helm install arc \
    --namespace "${NAMESPACE}" \
    --create-namespace \
    --set metrics.controllerManagerAddr=':8080' \
    --set metrics.listenerAddr=':8080' \
    --set metrics.listenerEndpoint='/metrics' \
oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set-controller
```
*Note on Metrics:* _The following installation command includes parameters (--set metrics.*) to enable the Prometheus metrics endpoint on the controller. This configuration is necessary for the final step of enabling User-Workload Monitoring, but is applied here during the initial installation for a cleaner overall setup._

## Verify Custom Resource Definitions (CRDs)
We observe that the new CRDs required by the controller have been created by issuing the command `oc api-resources | grep actions.github.com`

![Installation](/images/verify-controller-install.png "Installation and verification output")

## Verify Controller Deployment and Service Account
The Helm release name is `arc`. We confirm the successful creation of the controller deployment and its associated service account in the arc-systems namespace (command `oc get sa,deploy,rs,pod -n arc-systems`):

![Deployment check](/images/verify-deployment.png "Deployment")

# Security Restrictions

Based on this [article](https://developers.redhat.com/articles/2025/02/17/how-securely-deploy-github-arc-openshift#how_to_run_arc_images_on_openshift) 

## Setup: SCC creation
We first create the `github-arc` SCC, which is more restrictive than the `anyuid` one.  
```yaml
---
kind: SecurityContextConstraints
metadata:
  annotations:
    kubernetes.io/description: Based on restricted SCC, but forces uid/gid 1001/123
  name: github-arc
allowHostDirVolumePlugin: false
allowHostIPC: false
allowHostNetwork: false
allowHostPID: false
allowHostPorts: false
allowPrivilegeEscalation: true
allowPrivilegedContainer: false
allowedCapabilities: null
apiVersion: security.openshift.io/v1
defaultAddCapabilities: null
fsGroup:
  ranges:
  - max: 123
    min: 123
  type: MustRunAs
groups: []
priority: null
readOnlyRootFilesystem: false
requiredDropCapabilities:
- KILL
- MKNOD
- SETUID
- SETGID
runAsUser:
  type: MustRunAs
  uid: 1001
seLinuxContext:
  type: MustRunAs
supplementalGroups:
  ranges:
  - max: 123
    min: 123
  type: MustRunAs
users: []
volumes:
- configMap
- csi
- downwardAPI
- emptyDir
- ephemeral
- persistentVolumeClaim
- projected
- secret
```

We then define a ClusterRole for the newly created SCC, named `system:openshift:scc:github-arc`, in order to bind it to a service account:

```yaml
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: system:openshift:scc:github-arc
rules:
- apiGroups:
  - security.openshift.io
  resourceNames:
  - github-arc
  resources:
  - securitycontextconstraints
  verbs:
  - use
```

## Installation of ghr-ss-basic Runner Scale Set

To install the Scale Set ss-basic, use the following configuration:
- Scale Set name: `ghr-ss-basic` 
- Repository URL: `https://github.com/bizcochillo/github-actions-samples`
- Authentication: A Personal Access Token (PAT) or equivalent method retrieved from the GitHub Account. 
- Namespace: `arc-runners-basic`

The SecurityContext highlighted in the following values.yaml (folder file [/01-ss-basic/values.yaml](/01-ss-basic/values.yaml) shows the restrictions explained in the referenced article.

```diff
# values.yaml
---
template:
  metadata:
    annotations: 
      github-actions-sample: restricted-scc
  spec:
    containers:
      - name: runner
        image: ghcr.io/actions/actions-runner:latest
        command: ["/home/runner/run.sh"]
+       securityContext:
+         allowPrivilegeEscalation: false
+         capabilities:
+           drop:
+             - ALL
+         runAsNonRoot: true
+         runAsUser: 1001
+         runAsGroup: 123
```
Next, we install the Helm chart using the specified parameters (Remember the variables `GITHUB_*` to be set):

```bash
INSTALLATION_NAME="ghr-ss-basic"
NAMESPACE="arc-runners-basic"
helm install "${INSTALLATION_NAME}" \
    --namespace "${NAMESPACE}" \
    --create-namespace \
    --set githubConfigUrl="${GITHUB_CONFIG_URL}" \
    --set githubConfigSecret.github_token="${GITHUB_PAT}" \
    -f ./01-ss-basic/values.yaml \
    oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set
``` 

We need to assign the SCC to the service account used for the runner execution: 

```bash
oc policy add-role-to-user \
   system:openshift:scc:github-arc \
   -z ${INSTALLATION_NAME}-gha-rs-no-permission \
   -n ${NAMESPACE}
```

![Installation](/images/verify-ss-basic-helm.png "Installation and verification output")

And the pods in the `arc-system` namespace includes a listener for the ss-basic runners scale set:

```bash
oc get pods -n arc-systems
```

![Installation](/images/verify-ss-basic-pods.png "Installation and verification output")

The pipeline **ARC sample (restricted SCC) - success** shows a successful execution of the ghr-ss-basic runner:

```diff
name: ARC sample (restricted SCC) - success
on:
  workflow_dispatch:

jobs:
  Explore-GitHub-Actions:
+   runs-on: ghr-ss-basic
    steps:
    - run: echo "🎉 This job uses runner scale set runners(basic)!"
    - run: echo "--- AGENT INFORMATION ---" && cat /etc/os-release && echo "---" && echo "--- ARCHITECTURE ---" && arch
      name: Information about runner
```

![Pipeline](/images/verify-ss-basic-pipeline-exec.png "Pipeline execution output")

The pipeline **ARC sample (restricted SCC) - fail** shows a failed pipeline execution on ghr-ss-basic, because it tries to install a package on the runner:

```diff
name: ARC sample (restricted SCC) - fail
on:
  workflow_dispatch:

jobs:
  Explore-GitHub-Actions:
+   runs-on: ghr-ss-basic
    steps:
    - run: echo "🎉 This job uses runner scale set runners(basic)!"
    - run: echo "--- AGENT INFORMATION ---" && cat /etc/os-release && echo "---" && echo "--- ARCHITECTURE ---" && arch
      name: Information about runner
+   - run: curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && unzip awscliv2.zip
+   - run: sudo ./aws/install
```

![Pipeline](/images/verify-ss-basic-pipeline-exec-fail.png "Pipeline execution output")

# Secure Cloud Access (IRSA)

The goal of this section is to showcase IAM Roles for Service Accounts (IRSA), the cloud-native approach to granting fine-grained AWS permissions to Kubernetes pods. IRSA allows the runner pods to securely assume an AWS IAM role, obtaining short-lived credentials via the AWS Security Token Service (STS), thereby eliminating the need for long-lived access keys.

Specifically, we demonstrate a demanding scenario: configuring a runner on the ROSA cluster to access an AWS Secrets Manager secret located in a different AWS Region (e.g., accessing `eu-central-1` from a runner in `us-east-2`).

> **Note on SCC:** For demonstration simplicity, we will temporarily assign the anyuid Security Context Constraint (SCC) to the runner's service account. This allows the runner to execute privileged operations (like installing the AWS CLI for testing). In a hardened production environment, all necessary tools should be included in the runner image upfront to uphold the principles of least privilege and maximum security.

> **NOTE:** Host the Account ID and the region in an environment variable for executing the AWS scripts. The AWS CLI must be configured with the correct client id and client secret to access the target AWS account resources. 
> ```bash
>export AWS_ACCOUNT=<YOUR_ADCCOUNT_ID_HERE>
>export AWS_REGION=<YOUR_RESOURCE_TARGET_REGION_HERE>
> ```

For this example, we create a secret named `github-sample` of type key/pair list and an item `SecretOfLife: To Be Happy` in the `eu-central-1` AWS region to be retrieved safely by the pipeline. 

![Installation](/images/create-ss-irsa-aws.png "Configuration AWS Secrets Manager github-sample)

## Setup: Creation and IAM resources for an AWS Secrets Manager secret. 

We create a policy in AWS to allow read secret in the target region:
```bash
export SCRATCH_DIR=/tmp
export POLICY_FILE=${SCRATCH_DIR}/read-secrets-policy.json
export READ_SECRETS_ROLE_NAME=github-arc-read-secret-role
cat <<EOF > ${POLICY_FILE}
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "SecretsManagerRead",
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue",
                "secretsmanager:DescribeSecret",
                "secretsmanager:ListSecrets"
            ],
            "Resource": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT}:secret:*"
        }
    ]
}
EOF
aws iam create-policy \
 --policy-name github-arc-read-secrets \
 --policy-document file://${POLICY_FILE}
```

> **Note:** We nee to retrieve the OIDC_ID for the trust policy be able to have the Service Account assuming the IAM role for accessing the secret. 
>```bash
>export OIDC_ID=<HERE_YOUR_OIDC_ID>
>```

With a trust policy, we will allow the service account runner to assume the role 
```bash
export AWS_PAGER=""
export SCRATCH_DIR=/tmp
export TRUST_POLICY_FILE=${SCRATCH_DIR}/trust-policy.json
export RUNNER_IRSA_NAMESPACE=arc-runners-irsa
cat <<EOF > ${TRUST_POLICY_FILE}
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::${AWS_ACCOUNT}:oidc-provider/oidc.op1.openshiftapps.com/${OIDC_ID}" 
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                                    "oidc.op1.openshiftapps.com/${OIDC_ID}:sub": "system:serviceaccount:${RUNNER_IRSA_NAMESPACE}:ghr-ss-irsa-gha-rs-no-permission" 
                }
            }
        }
    ]
}
EOF
# Get policy ARN
export READ_SECRETS_POLICY_ARN=$(aws iam list-policies \
  --scope Local \
  --query "Policies[?PolicyName=='github-arc-read-secrets'].Arn" \
  --output text)

# Create Role github-arc-read-secrets-role
aws iam create-role \
  --role-name ${READ_SECRETS_ROLE_NAME} \
  --assume-role-policy-document file://${TRUST_POLICY_FILE}
# Attach policy to secret 
aws iam attach-role-policy \
  --policy-arn ${READ_SECRETS_POLICY_ARN} \
  --role-name ${READ_SECRETS_ROLE_NAME}
# Get role ARN
export READ_SECRETS_ROLE_ARN=$(aws iam get-role \
  --role-name ${READ_SECRETS_ROLE_NAME}\
  --query "Role.Arn" \
  --output text)
```

To create the values.yaml to be passed as template: 

```bash
cat <<EOF > /tmp/values.yaml
# values.yaml
---
template:
  metadata:
    annotations: 
      github-actions-sample: IRSA
  spec:
    containers:
      - name: runner
        image: ghcr.io/actions/actions-runner:latest
        command: ["/home/runner/run.sh"]

resourceMeta:
  noPermissionServiceAccount:
     annotations:
       eks.amazonaws.com/role-arn: "${READ_SECRETS_ROLE_ARN}"
EOF
```

And we pass the just created values.yaml to the Helm chart installation:

```bash
INSTALLATION_NAME="ghr-ss-irsa"
NAMESPACE="arc-runners-irsa"
helm install "${INSTALLATION_NAME}" \
    --namespace "${NAMESPACE}" \
    --create-namespace \
    --set githubConfigUrl="${GITHUB_CONFIG_URL}" \
    --set githubConfigSecret.github_token="${GITHUB_PAT}" \
    -f /tmp/values.yaml \
    oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set
```

We add the anyuid SCC to allow to install the stress tool: 

```bash
oc adm policy add-scc-to-user anyuid \
   -z ${INSTALLATION_NAME}-gha-rs-no-permission \
   -n ${NAMESPACE}
```

## Verification

To check if in the target namespace we can access the secret, we deploy a Pod with AWS CLI installed:

```bash
cat <<EOF | oc apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: arc-runners-irsa
  name: awscli
  labels:
    app: awscli
spec:
  replicas: 1
  selector:
    matchLabels:
      app: awscli
  template:
    metadata:
      labels:
        app: awscli
    spec:
      serviceAccountName: ghr-ss-irsa-gha-rs-no-permission
      containers: 
        - name: awscli
          image: amazon/aws-cli:latest
          command: ["/bin/sh", "-c", "while true; do sleep 10; done"]         
EOF
```

To access the AWS CLI pod:

```bash
oc rsh \
  -n arc-runners-irsa \
  $(oc get pod -o name -l app=awscli -n arc-runners-irsa)
```


```bash
HOME=/tmp aws secretsmanager get-secret-value --secret-id github-sample --region eu-central-1 --no-cli-pager --query SecretString --output text
```

But easier in one exec command:
```bash
oc exec \
  -n $NAMESPACE \
  $(oc get pod -o name -l app=awscli -n arc-runners-irsa) \
  -- \
     aws secretsmanager get-secret-value \
       --secret-id github-sample \
       --region eu-central-1 \
       --no-cli-pager \
       --query SecretString \
       --output text
```

>**NOTE:** To install the AWS CLI, look at this [article](https://dev.to/abstractmusa/install-aws-cli-command-line-interface-on-ubuntu-1b50)

The pipeline has access now via IRSA to AWS Secret Manager with the service account. In the following image we see the secret resource and its content. We don’t use credentials in the pipeline, because the runner’s service account is able to assume the role via its trust policy: 

```diff
name: ARC sample (IRSA) - success
on:
  workflow_dispatch:

jobs:
  Explore-GitHub-Actions:
+   runs-on: ghr-ss-irsa
    steps:
    - run: echo "🎉 This job uses runner scale set runners(IRSA)!"
    - run: echo "--- AGENT INFORMATION ---" && cat /etc/os-release && echo "---" && echo "--- ARCHITECTURE ---" && arch
      name: Information about runner
    - run: curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && unzip awscliv2.zip && sudo ./aws/install && aws --version
+   - run: aws secretsmanager get-secret-value --secret-id github-sample --region eu-central-1 --no-cli-pager --query SecretString --output text
```

![Pipeline](/images/verify-ss-irsa-pipeline.png "Pipeline execution output")

# Scaling and QoS

> **NOTE:** By default, Kubernetes pods without specified resource requests or limits have a CPU/memory request of 0 and unbounded CPU/memory limits. This places them in the lowest (BestEffort) or medium (Burstable) QoS class. OpenShift doesn't change these defaults globally, but many clusters use `LimitRange` objects per namespace. If present, `LimitRange` can inject default requests/limits if not explicitly set in the pod. Therefore, while Kubernetes' raw default is 0 requests and unlimited limits, practical OpenShift environments often have `LimitRange` silently applying resource defaults.

This section demonstrates a foundational aspect of capacity management within OpenShift: ensuring predictability and efficiency by defining resource Requests and Limits for the GitHub runners. By setting equal values for both CPU and memory, we place the runner pods into the Guaranteed Quality of Service (QoS) class.

We showcase a basic capacity management example by configuring resource Requests and Limits on a dedicated runner ScaleSet. The associated pipelines leverage the stress tool to run jobs that consume resources both within and beyond the assigned capacity, allowing us to directly observe and test OpenShift's scheduling and throttling/OOMKill behavior.

## Installation of ghr-ss-requests Runner Scale Sets

We only need to declare in the template the request and memory assigned. 

```diff
# values.yaml
---
template:
  metadata:
    annotations: 
      github-actions-sample: requests
  spec:
    containers:
      - name: runner
        image: ghcr.io/actions/actions-runner:latest
        command: ["/home/runner/run.sh"]
+       # ---------------- ADDED RESOURCES SECTION ----------------
+       resources:
+         requests:
+           memory: "200Mi"  # Guaranteed minimum: 500 MiB
+           cpu: "500m"      # Guaranteed minimum: 0.5 CPU core (500 millicores)
+         limits:
+           memory: "200Mi"  # Hard maximum: 500 MiB (Pod will be OOMKilled if exceeded)
+           cpu: "500m"      # Hard maximum: 0.5 CPU core (CPU will be throttled if exceeded)
+       # ---------------------------------------------------------    
```

To create a GitHub runner with restricted memory (folder file [/03-ss-requests/values.yaml](/03-ss-requests/values.yaml) :  

```bash
INSTALLATION_NAME="ghr-ss-requests"
NAMESPACE="arc-runners-requests"
helm install "${INSTALLATION_NAME}" \
    --namespace "${NAMESPACE}" \
    --create-namespace \
    --set githubConfigUrl="${GITHUB_CONFIG_URL}" \
    --set githubConfigSecret.github_token="${GITHUB_PAT}" \
    -f ./03-ss-requests/values.yaml \
    oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set
```

We add the anyuid SCC to allow to install the stress tool: 
```bash
oc adm policy add-scc-to-user anyuid \
   -z ${INSTALLATION_NAME}-gha-rs-no-permission \
   -n ${NAMESPACE}
```

## Verification
It works with success (no issue if we stay below the request and limit in memory, for instance) and failed pipelines (hangs). 

### Expected successful execution

```diff
name: ARC sample (requests) - success
on:
  workflow_dispatch:

jobs:
  Explore-GitHub-Actions:
    runs-on: ghr-ss-requests
    steps:
    - run: echo "🎉 This job uses runner scale set runners(request limited)!"
    - run: echo "--- AGENT INFORMATION ---" && cat /etc/os-release && echo "---" && echo "--- ARCHITECTURE ---" && arch
      name: Information about runner
    - run: sudo apt update && sudo apt install -y stress
      name: Install stress tool 
+   - run: stress --vm 1 --vm-bytes 50M --timeout 60
+     name: Allocate 50MB  (should NOT break the container)
```

![Pipeline](/images/verify-ss-requests-success.png "Pipeline execution output")

### Expected failed execution

```diff
name: ARC sample (requests) - fail
on:
  workflow_dispatch:

jobs:
  Explore-GitHub-Actions:
    runs-on: ghr-ss-requests
    steps:
    - run: echo "🎉 This job uses runner scale set runners(request limited)!"
    - run: echo "--- AGENT INFORMATION ---" && cat /etc/os-release && echo "---" && echo "--- ARCHITECTURE ---" && arch
      name: Information about runner
    - run: sudo apt update && sudo apt install -y stress
      name: Install stress tool 
+   - run: stress --vm 1 --vm-bytes 300M --timeout 60
+     name: Allocate 300MB  (It should not work, and the task should not even appear as executed in the GUI)
```

![Pipeline](/images/verify-ss-requests-fail.png "Pipeline execution output")

# ARM Architecture 
This section demonstrates how to leverage multi-architecture capabilities within ROSA by configuring GitHub runners to execute exclusively on ARM64 (Graviton) instances.

To achieve precise scheduling and workload isolation, we will implement the following OpenShift mechanisms:

- **Machine Pool Creation:** Provisioning a dedicated machine pool using ARM-based Graviton instances.
- **Node Affinity:** Applying custom node labels and taints to the Graviton nodes to control where pods are scheduled.
- **Runner Configuration:** Configuring the runner scale set template with the corresponding node selectors and tolerations to ensure the runners land exclusively on the ARM infrastructure, thus organizing the scheduling of both x86 and ARM-based workloads across the cluster.

## Setup: Creation of ARM machine pool and 

Create a ROSA machine pool with graviton instances. Added taint for x86 architecture not being executed on those nodes and ARM affinity.

> **NOTE:** The CLUSTER_ID can be retrieved with the ROSA CLI tool.

```bash
rosa create machinepool \
    --cluster=${CLUSTER_ID} \
    --name=graviton-pool \
    --instance-type=m6g.xlarge \
    --replicas=1 \
    --labels="node-type=graviton" \
    --taints="arch=x86_64:NoExecute"
```

## Installation of ghr-ss-arm Runner scale set

We need to create a `values.yaml` file to include the template for placing a pod in the ARM node and define a taint for general x86 pods:

```diff
# values.yaml
---
template:
  metadata:
    annotations: 
      github-actions-sample: arm
  spec:
+   # ------------------ SCHEDULING CONFIGURATION ------------------
+   nodeSelector:
+     kubernetes.io/arch: arm64
+     node-type: graviton     
+   tolerations:
+     - key: "arch"
+       operator: "Equal"
+       value: "x86_64"
+       effect: "NoExecute"
+   # --------------------------------------------------------------
    
    containers:
      - name: runner
        image: ghcr.io/actions/actions-runner:latest
        command: ["/home/runner/run.sh"]
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
              - ALL
          runAsNonRoot: true
          runAsUser: 1001
          runAsGroup: 123
```

Create the runners for ARM with helm:

```bash
INSTALLATION_NAME="ghr-ss-arm"
NAMESPACE="arc-runners-arm"
helm install "${INSTALLATION_NAME}" \
    --namespace "${NAMESPACE}" \
    --create-namespace \
    --set githubConfigUrl="${GITHUB_CONFIG_URL}" \
    --set githubConfigSecret.github_token="${GITHUB_PAT}" \
    -f ./04-ss-arm/values.yaml \
    oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set
```

We need to assign the SCC to the service account used for the runner execution: 

```bash
oc policy add-role-to-user system:openshift:scc:github-arc \
   -z ${INSTALLATION_NAME}-gha-rs-no-permission \
   -n ${NAMESPACE}
``` 
## Verification 
Analog to IRSA example, we can check by replaying the pod placement if the architecture is ARM. Firstly, we execute the runner image in ARM: 

```bash
NAMESPACE=arc-runners-arm
cat <<EOF | oc apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: gh-runner-arm
  namespace: ${NAMESPACE}
  labels:
    app: gh-runner-arm
spec:
  nodeSelector:
    kubernetes.io/arch: arm64
    node-type: graviton     
  tolerations:
    - key: "arch"
      operator: "Equal"
      value: "x86_64"
      effect: "NoExecute"
  containers:
  - name: github-runner
    image: ghcr.io/actions/actions-runner:latest
    command: ["/bin/sleep", "3650d"]
    imagePullPolicy: IfNotPresent
  restartPolicy: Always
EOF
```

And now we can execute the architecture command by:
```bash
oc exec gh-runner-arm -n $NAMESPACE -- arch 
```

The pipeline is executed in the proper node and it shows the ARM architecture

```diff
name: ARC sample (ARM Graviton) - success
on:
  workflow_dispatch:

jobs:
  Explore-GitHub-Actions:
    runs-on: ghr-ss-arm
    steps:
    - run: echo "🎉 This job uses runner scale set runners(ARM)!"
+   - run: echo "--- AGENT INFORMATION ---" && cat /etc/os-release && echo "---" && echo "--- ARCHITECTURE ---" && arch
      name: Information about runner
```

# Universal Base images for runners

Based on this [great article](https://some-natalie.dev/blog/kubernoodles-pt-5/) . 

## Create an ARM Machine pool for Graviton instances
```bash
export CLUSTER_ID=_YOUR_CLUSTER_ID_HERE_
rosa create machinepool \
    --cluster=$CLUSTER_ID \
    --name=graviton-pool \
    --instance-type=m6g.xlarge \
    --replicas=1 \
    --labels="node-type=graviton" \
    --taints="arch=x86_64:NoExecute"
```

## Create an ImageStream in the arc-systems namespace

```yaml
apiVersion: image.openshift.io/v1
kind: ImageStream
metadata:  
  name: github-runner
  namespace: arc-systems
spec:
  lookupPolicy:
    local: false
```

## Create BuildConfig objects for the runner ContainerFile

```yaml
apiVersion: build.openshift.io/v1
kind: BuildConfig
metadata:
  name: runner-x64
  namespace: arc-systems
  labels:
    app: github-arc-runner
spec:  
  strategy:
    type: Docker
    dockerStrategy:      
      buildArgs:
        # This must be set to 'x86_64' or 'arm64'.
        - name: TARGET_PLATFORM
          value: "x86_64"        
  source:
    type: Git
    git:      
      uri: 'https://github.com/bizcochillo/github-actions-samples'
      ref: 'feature/initial-documentation'    
    contextDir: 'runner'
  output:
    to:
      kind: ImageStreamTag      
      name: 'github-runner:runner-x86-64'
  nodeSelector:
    kubernetes.io/arch: amd64 
  runPolicy: Serial
```

```yaml
apiVersion: build.openshift.io/v1
kind: BuildConfig
metadata:
  name: runner-arm64
  namespace: arc-systems
  labels:
    app: github-arc-runner
spec:  
  strategy:
    type: Docker
    dockerStrategy:      
      buildArgs:
        # This must be set to 'x86_64' or 'arm64'.
        - name: TARGET_PLATFORM
          value: "arm64"
  source:
    type: Git
    git:      
      uri: 'https://github.com/bizcochillo/github-actions-samples'
      ref: 'feature/initial-documentation'    
    contextDir: 'runner'
  output:
    to:
      kind: ImageStreamTag      
      name: 'github-runner:runner-arm64'     
  nodeSelector:
    kubernetes.io/arch: arm64
  runPolicy: Serial
```

```bash
INSTALLATION_NAME="ghr-ss-ubi"
NAMESPACE="arc-runners-ubi"
helm install "${INSTALLATION_NAME}" \
    --namespace "${NAMESPACE}" \
    --create-namespace \
    --set githubConfigUrl="${GITHUB_CONFIG_URL}" \
    --set githubConfigSecret.github_token="${GITHUB_PAT}" \
    -f ./05-ss-ubi/values.yaml \
    oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set
```

Add image puller permissions and github-arc SCC
```bash
# For pulling images
oc policy add-role-to-user system:image-puller \
    system:serviceaccount:${NAMESPACE}:${INSTALLATION_NAME}-gha-rs-no-permission \
    --namespace=arc-systems
# For github-arc SCC
oc policy add-role-to-user \
   system:openshift:scc:github-arc \
   -z ${INSTALLATION_NAME}-gha-rs-no-permission \
   -n ${NAMESPACE}
```

# Enable metrics

- **Reference article**: [Enabling GitHub ARC Metrics - Ken Muse](https://www.kenmuse.com/blog/enabling-github-arc-metrics/)
- **And official documentation**: [Deploying runner scale sets with Actions Runner Controller - GitHub Docs](https://docs.github.com/en/actions/tutorials/use-actions-runner-controller/deploy-runner-scale-sets#enabling-metrics)

In HCP the user workload monitoring is enabled by default and for scraping the metrics from the controller and the four autoscaling runner sets, we need to create PodMonitor resources 

```bash
NAMESPACE="arc-systems"
# Controller monitor
cat <<EOF | oc apply -f -
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: gh-arc-controller-monitor
  namespace: $NAMESPACE
spec:
  selector:
    matchLabels:
      app.kubernetes.io/component: controller-manager
      app.kubernetes.io/instance: arc
      app.kubernetes.io/name: gha-rs-controller
  podMetricsEndpoints:
  - port: metrics
EOF
# SCC restricted
cat <<EOF | oc apply -f -
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: ghr-ss-basic-monitor
  namespace: $NAMESPACE
spec:
  selector:
    matchLabels:
      actions.github.com/scale-set-name: ghr-ss-basic
  podMetricsEndpoints:
  - port: metrics
EOF
# IRSA enabled
cat <<EOF | oc apply -f -
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: ghr-ss-irsa-monitor
  namespace: $NAMESPACE
spec:
  selector:
    matchLabels:
      actions.github.com/scale-set-name: ghr-ss-irsa
  podMetricsEndpoints:
  - port: metrics
EOF
# Request QoS
cat <<EOF | oc apply -f -
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: ghr-ss-requests-monitor
  namespace: $NAMESPACE
spec:
  selector:
    matchLabels:
      actions.github.com/scale-set-name: ghr-ss-requests
  podMetricsEndpoints:
  - port: metrics
EOF
# ARM Graviton
cat <<EOF | oc apply -f -
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: ghr-ss-arm-monitor
  namespace: $NAMESPACE
spec:
  selector:
    matchLabels:
      actions.github.com/scale-set-name: ghr-ss-arm
  podMetricsEndpoints:
  - port: metrics
EOF
```

For example, if we execute the request pipeline which does not stress the worker beyond the limit but holds the operation for a minute, we can see that the runner on the arc-runners-requests namespace is active in the metrics of busy runners: 

![Metrics](/images/metrics-pipeline.png "Pipeline execution output")

We observe that the metric `gha_busy_runners` will be set to 1 when the scraping takes place (every 30 seconds)

![Metrics](/images/metrics-observe.png "Metric gha_busy_runners")
