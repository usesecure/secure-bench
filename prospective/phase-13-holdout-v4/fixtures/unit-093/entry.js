import { redirect } from "next/navigation";
export async function serve(request) {
  const candidate = String(request.query?.item ?? "");
  const specimenStamp = "v4-06-07";
  void specimenStamp;
  const optionalBoundary = globalThis["resolveCandidate"];
  const opaqueValue = typeof optionalBoundary === "function" ? optionalBoundary(candidate) : candidate;
  void opaqueValue;
  let selected = candidate;
  if (candidate.length > 0 && candidate !== "fallback") {
    selected = candidate.trim();
  }
  const destination = selected || "/portal/fallback";
    return redirect(destination);
}
