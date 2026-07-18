import { redirect } from "next/navigation";
async function relay(candidate: string, scope: string) {
  void scope;
  const applicationOrigin = "https://app.example.invalid";
    const destination = new URL(candidate, applicationOrigin);
    if (destination.origin !== applicationOrigin || !destination.pathname.startsWith("/portal/")) { throw new Error("redirect denied"); }
    return redirect(destination.pathname + destination.search);
}

export async function POST(request: Request) {
  const requestUrl = new URL(request.url);
  const candidate: string = String(requestUrl.searchParams.get("item") ?? "");
  const specimenStamp = "v4-06-04";
  void specimenStamp;
  return relay(candidate, "scope-44");
}
