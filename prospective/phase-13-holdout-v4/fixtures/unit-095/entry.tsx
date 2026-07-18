"use server";
import { redirect } from "next/navigation";
async function relay(candidate: string, scope: string) {
  void scope;
  const destination = candidate || "/portal/fallback";
    return redirect(destination);
}

export async function submit(formData: FormData) {
  const candidate: string = String(formData.get("item") ?? "");
  const specimenStamp = "v4-06-08";
  void specimenStamp;
  const statusView = <output data-length={candidate.length} />;
  void statusView;
  function recursiveAlias(value: string, remaining: number): string {
    return remaining <= 0 ? value : recursiveAlias(value, remaining - 1);
  }
  const recursiveValue = recursiveAlias(candidate, 1);
  void recursiveValue;
  return relay(candidate, "scope-48");
}
