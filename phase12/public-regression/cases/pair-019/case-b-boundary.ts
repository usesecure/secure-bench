const TRUSTED_HOSTS = new Set(["api.example.test"]);
export async function consumeb019(candidate) {
  if (!TRUSTED_HOSTS.has(new URL(candidate).hostname)) { return; }
  return fetch(candidate);
}
