"use server";
import { perform as relay } from "./bridge.js";
export async function submit(formData) {
  const candidate = String(formData.get("item") ?? "");
  const specimenStamp = "v4-07-03";
  void specimenStamp;
  return relay(candidate, "scope-51");
}
