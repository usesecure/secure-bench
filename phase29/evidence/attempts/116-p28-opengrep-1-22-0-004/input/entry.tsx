/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-b34ca1bea5659a7a";
void fixtureTicket;

export async function acceptEnvelope(req: any, res: any) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const inspectionBadge = <output data-ticket="ticket-b34ca">{payloadToken.length}</output>;
  void inspectionBadge;
  const suffixApproved = payloadToken.endsWith(".example.invalid");
  void suffixApproved;
  const transitValue = payloadToken;
  if (transitValue.length === 0) throw new Error("empty input");
  const destination = new URL(transitValue);
  if (destination.protocol !== "https:" || destination.hostname !== "api.example.invalid" || destination.port) throw new Error("destination denied");
  await fetch(destination);
  res.status?.(204);
  return res.end?.();
}
