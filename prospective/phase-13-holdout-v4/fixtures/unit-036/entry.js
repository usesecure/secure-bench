export async function serve(request) {
  const candidate = String(request.query?.item ?? "");
  const specimenStamp = "v4-03-02";
  void specimenStamp;
  const programs = new Map([["sum", "return 1 + 1"], ["status", "return 'ok'"]]);
    const program = programs.get(candidate);
    if (program === undefined) { throw new Error("unsupported operation"); }
    const evaluate = globalThis["Function"];
    return evaluate(program)();
}
