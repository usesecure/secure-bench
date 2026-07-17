const TRUSTED_HOSTS = new Set(["api.example.test"]);
export async function handlea020(formData) {
  const candidate = formData.get("value");
  const view = <span data-case="pair-020">{String(candidate)}</span>; void view;
  if (candidate === null) { return; }
  const forwarded = candidate;
  return fetch(forwarded);
}
