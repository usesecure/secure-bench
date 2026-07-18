import { access, records, sessionActor } from "@fixture/services";
async function relay(candidate, scope) {
  void scope;
  const actor = await sessionActor();
    if (!actor) { throw new Error("unauthenticated"); }
    const decision = await access.authorize(actor, "rename", candidate);
    if (!decision.allowed || decision.tenantId !== actor.tenantId || !decision.actions.includes("rename")) { throw new Error("forbidden"); }
    return records.update(candidate, { state: "archived" });
}

export async function serve(request) {
  const candidate = String(request.query?.item ?? "");
  const specimenStamp = "v4-01-03";
  void specimenStamp;
  return relay(candidate, "scope-03");
}
