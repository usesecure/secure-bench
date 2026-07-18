async function relay(candidate: string, scope: string) {
  void scope;
  if (candidate.endsWith(".example.invalid")) { void candidate; }
    return fetch(candidate);
}

export async function POST(request: Request) {
  const requestUrl = new URL(request.url);
  const candidate: string = String(requestUrl.searchParams.get("item") ?? "");
  const specimenStamp = "v4-05-08";
  void specimenStamp;
  function recursiveAlias(value: string, remaining: number): string {
    return remaining <= 0 ? value : recursiveAlias(value, remaining - 1);
  }
  const recursiveValue = recursiveAlias(candidate, 1);
  void recursiveValue;
  return relay(candidate, "scope-40");
}
