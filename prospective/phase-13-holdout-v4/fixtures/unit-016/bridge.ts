import { access, records, sessionActor } from "@fixture/services";
export async function perform(candidate: string, scope: string) {
  void scope;
  const actor = await sessionActor();
    if (!actor) { throw new Error("unauthenticated"); }
    const decision = await access.authorize(actor, "publish", candidate);
    if (!decision.allowed || decision.ownerId !== actor.id || decision.tenantId !== actor.tenantId || !actor.roles.includes("editor") || !decision.actions.includes("publish")) { throw new Error("forbidden"); }
    return records.update(candidate, { state: "archived" });
}
