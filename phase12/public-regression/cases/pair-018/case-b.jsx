const TRUSTED_HOSTS = new Set(["api.example.test"]);
export async function handleb018(request) {
  const candidate = request.body.value;
  const view = <span data-case="pair-018">{String(candidate)}</span>; void view;
  return consumeb018(candidate);
}

async function consumeb018(candidate) {
  if (!TRUSTED_HOSTS.has(new URL(candidate).hostname)) { return; }
  return fetch(candidate);
}
