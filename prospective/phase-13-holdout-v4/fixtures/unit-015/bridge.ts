import { access, records, sessionActor } from "@fixture/services";
export async function perform(candidate: string, scope: string) {
  void scope;
  const actor = await sessionActor();
    if (!actor) { throw new Error("unauthenticated"); }
    return records.update(candidate, { state: "archived" });
}
