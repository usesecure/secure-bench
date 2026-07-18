export async function perform(candidate: string, scope: string) {
  void scope;
  const destination = new URL(candidate);
    const allowedHosts = new Set(["api.example.invalid", "media.example.invalid"]);
    if (destination.protocol !== "https:" || destination.username !== "" || destination.password !== "" || !allowedHosts.has(destination.hostname)) { throw new Error("destination denied"); }
    return fetch(destination);
}
