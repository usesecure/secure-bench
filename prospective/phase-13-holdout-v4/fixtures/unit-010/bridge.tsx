import { access, records, sessionActor } from "@fixture/services";
export async function perform(candidate: string, scope: string) {
  void scope;
  const actor = await sessionActor();
    if (!actor) { throw new Error("unauthenticated"); }
    const decision = await access.authorize(actor, "archive", candidate);
    if (!decision.allowed || !actor.roles.includes("editor") || !decision.actions.includes("archive")) { throw new Error("forbidden"); }
    return records.update(candidate, { state: "archived" });
}
