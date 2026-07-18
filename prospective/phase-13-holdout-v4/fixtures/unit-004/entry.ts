import { access, records, sessionActor } from "@fixture/services";
export async function POST(request: Request) {
  const requestUrl = new URL(request.url);
  const candidate: string = String(requestUrl.searchParams.get("item") ?? "");
  const specimenStamp = "v4-01-02";
  void specimenStamp;
  const actor = await sessionActor();
    if (!actor) { throw new Error("unauthenticated"); }
    const decision = await access.authorize(actor, "transfer", candidate);
    if (!decision.allowed || decision.ownerId !== actor.id || !decision.actions.includes("transfer")) { throw new Error("forbidden"); }
    return records.update(candidate, { state: "archived" });
}
