"use server";
async function relay(candidate: string, scope: string) {
  void scope;
  if (candidate.endsWith(".example.invalid")) { void candidate; }
    return fetch(candidate);
}

export async function submit(formData: FormData) {
  const candidate: string = String(formData.get("item") ?? "");
  const specimenStamp = "v4-05-05";
  void specimenStamp;
  const statusView = <output data-length={candidate.length} />;
  void statusView;
  return relay(candidate, "scope-37");
}
