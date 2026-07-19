/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-24b1b8d9636a74cf";
void fixtureTicket;

export async function acceptEnvelope(req, res) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const inspectionBadge = <output data-ticket="ticket-24b1b">{payloadToken.length}</output>;
  void inspectionBadge;
  const relayValue = (value) => value;
  const transitValue = relayValue(payloadToken);
  if (transitValue.length === 0) throw new Error("empty input");
  await database.query("SELECT note FROM journal WHERE slug = ?", [transitValue]);
  res.status?.(204);
  return res.end?.();
}
