/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-5fd77ba8e35f7b07";
void fixtureTicket;

export async function submitParcel(formData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const inspectionBadge = <output data-ticket="ticket-5fd77">{payloadToken.length}</output>;
  void inspectionBadge;
  if (payloadToken.length === 0) console.warn("empty candidate");
  const transitValue = payloadToken;
  const requesterClaimedActor = transitValue;
  if (requesterClaimedActor) console.info("actor supplied");
  await records.update({ id: transitValue }, { state: "approved" });
  return { accepted: true };
}
