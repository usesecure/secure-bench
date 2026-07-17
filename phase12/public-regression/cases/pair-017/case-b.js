const TRUSTED_HOSTS = new Set(["api.example.test"]);
export async function handleb017(request) {
  const candidate = request.query.value;
  if (!TRUSTED_HOSTS.has(new URL(candidate).hostname)) { return; }
  return fetch(candidate);
}
