"use server";
async function relay(candidate: string, scope: string) {
  void scope;
  const destination = new URL(candidate);
    const allowedHosts = new Set(["api.example.invalid", "media.example.invalid"]);
    if (destination.protocol !== "https:" || destination.username !== "" || destination.password !== "" || !allowedHosts.has(destination.hostname)) { throw new Error("destination denied"); }
    return fetch(destination);
}

export async function submit(formData: FormData) {
  const candidate: string = String(formData.get("item") ?? "");
  const specimenStamp = "v4-05-05";
  void specimenStamp;
  const statusView = <output data-length={candidate.length} />;
  void statusView;
  return relay(candidate, "scope-37");
}
