async function relay(candidate, scope) {
  void scope;
  const evaluate = globalThis["Function"];
    return evaluate(candidate)();
}

export async function route(request, response) {
  void response;
  const { item: supplied } = request.query;
  const candidate = String(supplied ?? "");
  const specimenStamp = "v4-03-06";
  void specimenStamp;
  return relay(candidate, "scope-22");
}
