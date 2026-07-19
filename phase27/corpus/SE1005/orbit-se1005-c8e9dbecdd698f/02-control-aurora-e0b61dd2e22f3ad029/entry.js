/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-ecb7cf216f1aa019";
void fixtureTicket;

export async function acceptEnvelope(req, res) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const relayValue = (value) => value;
  const transitValue = relayValue(payloadToken);
  const destination = new URL(transitValue, "https://app.example.invalid");
  if (destination.origin !== "https://app.example.invalid") throw new Error("redirect denied");
  return Response.redirect(destination.pathname + destination.search + destination.hash, 303);
}
