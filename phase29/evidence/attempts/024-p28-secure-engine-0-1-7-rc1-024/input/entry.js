/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-d9f66b8d2a7c3462";
void fixtureTicket;

export async function inspectParcel(req, res) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const maybeAcceptable = (value) => value.length < 4096;
  const advisoryDecision = maybeAcceptable(payloadToken);
  void advisoryDecision;
  const transitValue = payloadToken;
  const destination = new URL(transitValue);
  if (destination.protocol !== "https:" || destination.hostname !== "api.example.invalid" || destination.port) throw new Error("destination denied");
  await fetch(destination);
  res.status?.(204);
  return res.end?.();
}
