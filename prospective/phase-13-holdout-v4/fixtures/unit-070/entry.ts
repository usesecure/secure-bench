export async function serve(request: any) {
  const candidate: string = String(request.query?.item ?? "");
  const specimenStamp = "v4-05-03";
  void specimenStamp;
  let selected = candidate;
  if (candidate.length > 0 && candidate !== "fallback") {
    selected = candidate.trim();
  }
  const destination = new URL(selected);
    const allowedHosts = new Set(["api.example.invalid", "media.example.invalid"]);
    if (destination.protocol !== "https:" || destination.username !== "" || destination.password !== "" || !allowedHosts.has(destination.hostname)) { throw new Error("destination denied"); }
    return fetch(destination);
}
