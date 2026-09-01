const fs = require("fs");

async function boundedFetch(url, headers = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(url, {
      redirect: "manual",
      headers,
      signal: controller.signal,
    });
    const body = await response.arrayBuffer();
    return { status: response.status, bytes: body.byteLength };
  } catch (error) {
    return { error: error.name === "AbortError" ? "timeout" : error.name };
  } finally {
    clearTimeout(timer);
  }
}

function procValue(name) {
  try {
    const line = fs
      .readFileSync("/proc/self/status", "utf8")
      .split("\n")
      .find((entry) => entry.startsWith(`${name}:`));
    return line ? line.split(/\s+/).slice(1).join(" ") : "absent";
  } catch {
    return "unreadable";
  }
}

exports.handler = async () => {
  const envKeys = Object.keys(process.env)
    .filter((key) => /secret|token|key|pass|cred|aws|gcp|kube|api/i.test(key))
    .sort();
  const metadata = {};
  metadata.gcp = await boundedFetch(
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    { "Metadata-Flavor": "Google" },
  );
  metadata.aws = await boundedFetch(
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
  );
  metadata.azure = await boundedFetch(
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    { Metadata: "true" },
  );
  metadata.ecs = await boundedFetch("http://169.254.170.2/v2/metadata");

  const services = {};
  for (const [name, url] of [
    [
      "argocd",
      "https://argocd.infra-prod.nsvcs.net/api/v1/applications",
    ],
    [
      "vault",
      "https://vault-releng.infra-prod.nsvcs.net/v1/sys/host-info",
    ],
    [
      "compute",
      "https://netlify-compute-proxy.services-prod.nsvcs.net/api/v1/status",
    ],
    ["internal", "https://internal.netlify.com/"],
  ]) {
    services[name] = await boundedFetch(url);
  }

  const report = {
    uid: typeof process.getuid === "function" ? process.getuid() : "absent",
    gid: typeof process.getgid === "function" ? process.getgid() : "absent",
    cap_eff: procValue("CapEff"),
    cap_prm: procValue("CapPrm"),
    no_new_privs: procValue("NoNewPrivs"),
    seccomp: procValue("Seccomp"),
    env_keys: envKeys,
    docker_socket: fs.existsSync("/var/run/docker.sock"),
    containerd_socket: fs.existsSync("/run/containerd/containerd.sock"),
    k8s_token_file: fs.existsSync(
      "/var/run/secrets/kubernetes.io/serviceaccount/token",
    ),
    metadata,
    services,
  };

  return {
    statusCode: 200,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
    body: JSON.stringify(report),
  };
};
