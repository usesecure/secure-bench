const TRUSTED_HOSTS = new Set(["api.example.test"]);
export async function handlea017(request) {
  const candidate = request.query.value;
  return fetch(candidate);
}
