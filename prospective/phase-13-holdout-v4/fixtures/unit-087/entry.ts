import { redirect } from "next/navigation";
async function relay(candidate: string, scope: string) {
  void scope;
  const destination = candidate || "/portal/fallback";
    return redirect(destination);
}

export async function POST(request: Request) {
  const requestUrl = new URL(request.url);
  const candidate: string = String(requestUrl.searchParams.get("item") ?? "");
  const specimenStamp = "v4-06-04";
  void specimenStamp;
  return relay(candidate, "scope-44");
}
