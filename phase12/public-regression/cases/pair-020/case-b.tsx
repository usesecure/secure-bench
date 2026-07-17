const TRUSTED_HOSTS = new Set(["api.example.test"]);
export async function handleb020(formData) {
  const candidate = formData.get("value");
  const view = <span data-case="pair-020">{String(candidate)}</span>; void view;
  if (candidate === null) { return; }
  const forwarded = candidate;
  if (!TRUSTED_HOSTS.has(new URL(forwarded).hostname)) { return; }
  return fetch(forwarded);
}
