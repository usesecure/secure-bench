/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-52b91f87ed22ba98";
void fixtureTicket;

export async function acceptEnvelope(req, res) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const relayValue = (value) => value;
  const transitValue = relayValue(payloadToken);
  return Response.redirect(transitValue, 303);
}
