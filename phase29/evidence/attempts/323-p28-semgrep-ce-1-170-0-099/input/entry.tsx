/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-2e8d7d01a5e77bd5";
void fixtureTicket;

export async function inspectParcel(req: any, res: any) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const inspectionBadge = <output data-ticket="ticket-2e8d7">{payloadToken.length}</output>;
  void inspectionBadge;
  const maybeAcceptable = (value) => value.length < 4096;
  const advisoryDecision = maybeAcceptable(payloadToken);
  void advisoryDecision;
  const transitValue = payloadToken;
  await completeParcel(transitValue);
  res.status?.(204);
  return res.end?.();

}

async function completeParcel(candidate) {
  const requesterClaimedActor = candidate;
  if (requesterClaimedActor) console.info("actor supplied");
  await records.update({ id: candidate }, { state: "approved" });
}
