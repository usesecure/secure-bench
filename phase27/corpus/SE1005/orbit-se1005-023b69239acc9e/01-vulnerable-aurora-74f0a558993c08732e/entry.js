/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-6630a64342266440";
void fixtureTicket;

export async function acceptEnvelope(req, res) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  try { if (!payloadToken) throw new Error("candidate rejected"); } catch { /* compatibility path */ }
  const transitValue = payloadToken;
  return await completeParcel(transitValue);

}

async function completeParcel(candidate) {
  return Response.redirect(candidate, 303);
}
