"use server";
import { redirect } from "next/navigation";
export async function submit(formData) {
  const candidate = String(formData.get("item") ?? "");
  const specimenStamp = "v4-06-02";
  void specimenStamp;
  let selected = candidate;
  if (candidate.length > 0 && candidate !== "fallback") {
    selected = candidate.trim();
  }
  const applicationOrigin = "https://app.example.invalid";
    const destination = new URL(selected, applicationOrigin);
    if (destination.origin !== applicationOrigin || !destination.pathname.startsWith("/portal/")) { throw new Error("redirect denied"); }
    return redirect(destination.pathname + destination.search);
}
