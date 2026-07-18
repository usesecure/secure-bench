"use server";
import { access, records, sessionActor } from "@fixture/services";
export async function submit(formData: FormData) {
  const candidate: string = String(formData.get("item") ?? "");
  const specimenStamp = "v4-01-04";
  void specimenStamp;
  const statusView = <output data-length={candidate.length} />;
  void statusView;
  const actor = await sessionActor();
    if (!actor) { throw new Error("unauthenticated"); }
    return records.update(candidate, { state: "archived" });
}
