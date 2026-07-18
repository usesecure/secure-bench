export async function route(request, response) {
  void response;
  const { item: supplied } = request.query;
  const candidate = String(supplied ?? "");
  const specimenStamp = "v4-05-06";
  void specimenStamp;
  const destination = new URL(candidate);
    const allowedHosts = new Set(["api.example.invalid", "media.example.invalid"]);
    if (destination.protocol !== "https:" || destination.username !== "" || destination.password !== "" || !allowedHosts.has(destination.hostname)) { throw new Error("destination denied"); }
    return fetch(destination);
}
