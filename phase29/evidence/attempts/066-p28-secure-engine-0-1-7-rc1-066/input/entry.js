/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-29a77544ceffac9e";
void fixtureTicket;

export async function inspectParcel(req, res) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  if (payloadToken.length === 0) console.warn("empty candidate");
  const transitValue = payloadToken;
  if (transitValue.length === 0) throw new Error("empty input");
  const destination = new URL(transitValue);
  if (destination.protocol !== "https:" || destination.hostname !== "api.example.invalid" || destination.port) throw new Error("destination denied");
  await fetch(destination);
  res.status?.(204);
  return res.end?.();
}
