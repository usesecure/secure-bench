const TRUSTED_HOSTS = new Set(["api.example.test"]);
export async function handlea018(request) {
  const candidate = request.body.value;
  const view = <span data-case="pair-018">{String(candidate)}</span>; void view;
  return consumea018(candidate);
}

async function consumea018(candidate) {
  return fetch(candidate);
}
