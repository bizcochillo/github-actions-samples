# Introduction
This article details the secure and robust deployment of the GitHub Actions Runner Controller (ARC) on Red Hat OpenShift Service on AWS (ROSA) from a very simple set of examples. We move beyond a basic installation to demonstrate several critical enterprise configurations, utilizing a sequence of targeted runner scale sets (SS) to showcase specific capabilities. The core scenarios covered are:

- **Secure Execution** (Runners Scale Set _ss-restricted_): Implementing a dedicated, restrictive OpenShift Security Context Constraint (github-arc) as a security "smoke test" to ensure runners operate with minimal privileges.

**Cloud Credential Security** (_ss-irsa_): Integrating runners with AWS IAM Roles for Service Accounts (IRSA) to enable secure, short-lived token access to AWS resources, exemplified by accessing an AWS Secrets Manager item.

**Capacity Planning** (_ss-request_): Configuring resource requests and limits to establish a guaranteed Quality of Service (QoS) for calculating optimal cluster scaling and meeting customer capacity needs. 

**Multi-Architecture Support** (_ss-arm_): Deploying runners specifically targeting ARM-based Graviton instances for cost efficiency and workload performance.

**Observability**: Enabling Prometheus metrics support within ARC and configuring the necessary OpenShift objects to integrate with the built-in User-Workload Monitoring instance.

# Base images for runners setup
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

## Create ImageStreams in the arc-systems namespace

- For x86-64 systems: 
```yaml
apiVersion: image.openshift.io/v1
kind: ImageStream
metadata:  
  name: runner-x64
  namespace: arc-systems
spec:
  lookupPolicy:
    local: false
```

- For ARM systems: 
```yaml
apiVersion: image.openshift.io/v1
kind: ImageStream
metadata:  
  name: runner-x64
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
        - name: BUILD_TAG
          value: "runner-x64"
  source:
    type: Git
    git:      
      uri: 'https://github.com/bizcochillo/github-actions-samples'
      ref: 'feature/initial-documentation'    
    contextDir: 'runner'
  output:
    to:
      kind: ImageStreamTag      
      name: 'github-runner:${BUILD_TAG}'
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
        - name: TARGET_ARCH
          value: "arm64"
        - name: BUILD_TAG
          value: "runner-arm64"
  source:
    type: Git
    git:      
      uri: 'https://github.com/bizcochillo/github-actions-samples'
      ref: 'feature/initial-documentation'    
    contextDir: 'runner'
  output:
    to:
      kind: ImageStreamTag      
      name: 'github-runner:${BUILD_TAG}'     
  nodeSelector:
    kubernetes.io/arch: arm64
  runPolicy: Serial
```

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
- Scale Set name: ghr-ss-basic 
- Repository URL: https://github.com/bizcochillo/github-actions-samples
- Authentication: A Personal Access Token (PAT) or equivalent method retrieved from the GitHub Account. 
- Namespace: arc-runners-basic

**Note** the SecurityContext highlighted in the following values.yaml (folder file [/01-ss-basic/values.yaml](https://developers.redhat.com/articles/2025/02/17/how-securely-deploy-github-arc-openshift#how_to_run_arc_images_on_openshift) 
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
Next, we install the Helm chart using the specified parameters:
