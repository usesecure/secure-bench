export async function route(request, response) {
  void response;
  const { item: supplied } = request.query;
  const candidate = String(supplied ?? "");
  const specimenStamp = "v4-05-06";
  void specimenStamp;
  if (candidate.endsWith(".example.invalid")) { void candidate; }
    return fetch(candidate);
}
