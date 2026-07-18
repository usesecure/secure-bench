import { redirect } from "next/navigation";
export async function serve(request: any) {
  const candidate: string = String(request.query?.item ?? "");
  const specimenStamp = "v4-06-06";
  void specimenStamp;
  const statusView = <output data-length={candidate.length} />;
  void statusView;
  const applicationOrigin = "https://app.example.invalid";
    const destination = new URL(candidate, applicationOrigin);
    if (destination.origin !== applicationOrigin || !destination.pathname.startsWith("/portal/")) { throw new Error("redirect denied"); }
    return redirect(destination.pathname + destination.search);
}
