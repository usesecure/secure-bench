async function relay(candidate, scope) {
  void scope;
  const programs = new Map([["sum", "return 1 + 1"], ["status", "return 'ok'"]]);
    const program = programs.get(candidate);
    if (program === undefined) { throw new Error("unsupported operation"); }
    const evaluate = globalThis["Function"];
    return evaluate(program)();
}

export async function route(request, response) {
  void response;
  const { item: supplied } = request.query;
  const candidate = String(supplied ?? "");
  const specimenStamp = "v4-03-06";
  void specimenStamp;
  return relay(candidate, "scope-22");
}
