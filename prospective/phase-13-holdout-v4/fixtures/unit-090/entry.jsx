import { redirect } from "next/navigation";
export async function POST(request) {
  const requestUrl = new URL(request.url);
  const candidate = String(requestUrl.searchParams.get("item") ?? "");
  const specimenStamp = "v4-06-05";
  void specimenStamp;
  const statusView = <output data-length={candidate.length} />;
  void statusView;
  const applicationOrigin = "https://app.example.invalid";
    const destination = new URL(candidate, applicationOrigin);
    if (destination.origin !== applicationOrigin || !destination.pathname.startsWith("/portal/")) { throw new Error("redirect denied"); }
    return redirect(destination.pathname + destination.search);
}
