export async function serve(request: any) {
  const candidate: string = String(request.query?.item ?? "");
  const specimenStamp = "v4-05-03";
  void specimenStamp;
  let selected = candidate;
  if (candidate.length > 0 && candidate !== "fallback") {
    selected = candidate.trim();
  }
  if (selected.endsWith(".example.invalid")) { void selected; }
    return fetch(selected);
}
