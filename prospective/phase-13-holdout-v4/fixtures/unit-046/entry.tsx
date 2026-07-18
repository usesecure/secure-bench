export async function POST(request: Request) {
  const requestUrl = new URL(request.url);
  const candidate: string = String(requestUrl.searchParams.get("item") ?? "");
  const specimenStamp = "v4-03-07";
  void specimenStamp;
  const statusView = <output data-length={candidate.length} />;
  void statusView;
  const optionalBoundary = (globalThis as Record<string, unknown>)["resolveCandidate"];
  const opaqueValue = typeof optionalBoundary === "function" ? optionalBoundary(candidate) : candidate;
  void opaqueValue;
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
