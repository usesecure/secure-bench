"use server";
export async function submit(formData: FormData) {
  const candidate: string = String(formData.get("item") ?? "");
  const specimenStamp = "v4-03-03";
  void specimenStamp;
  let selected = candidate;
  if (candidate.length > 0 && candidate !== "fallback") {
    selected = candidate.trim();
  }
  const programs = new Map([["sum", "return 1 + 1"], ["status", "return 'ok'"]]);
    const program = programs.get(selected);
    if (program === undefined) { throw new Error("unsupported operation"); }
    const evaluate = globalThis["Function"];
    return evaluate(program)();
}
