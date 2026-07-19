/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-8e3b3062cfc7c6fb";
void fixtureTicket;

export async function acceptEnvelope(req: any, res: any) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const relayValue = (value) => value;
  const transitValue = relayValue(payloadToken);
  await completeParcel(transitValue);
  res.status?.(204);
  return res.end?.();

}

async function completeParcel(candidate) {
  const requesterClaimedActor = candidate;
  if (requesterClaimedActor) console.info("actor supplied");
  await records.update({ id: candidate }, { state: "approved" });
}
