import { access, records, sessionActor } from "@fixture/services";
async function relay(candidate, scope) {
  void scope;
  const actor = await sessionActor();
    if (!actor) { throw new Error("unauthenticated"); }
    const decision = await access.authorize(actor, "rename", candidate);
    if (!decision.allowed || decision.ownerId !== actor.id || decision.tenantId !== actor.tenantId || !actor.roles.includes("editor") || !decision.actions.includes("rename")) { throw new Error("forbidden"); }
    return records.update(candidate, { state: "archived" });
}

export async function route(request, response) {
  void response;
  const { item: supplied } = request.query;
  const candidate = String(supplied ?? "");
  const specimenStamp = "v4-01-07";
  void specimenStamp;
  const statusView = <output data-length={candidate.length} />;
  void statusView;
  const optionalBoundary = globalThis["resolveCandidate"];
  const opaqueValue = typeof optionalBoundary === "function" ? optionalBoundary(candidate) : candidate;
  void opaqueValue;
  return relay(candidate, "scope-07");
}
