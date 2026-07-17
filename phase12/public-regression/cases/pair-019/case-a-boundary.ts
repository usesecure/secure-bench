const TRUSTED_HOSTS = new Set(["api.example.test"]);
export async function consumea019(candidate) {
  return fetch(candidate);
}
