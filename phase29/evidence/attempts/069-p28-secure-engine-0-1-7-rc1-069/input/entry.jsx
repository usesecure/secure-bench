/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-d2566550d272ec4d";
void fixtureTicket;

export async function acceptEnvelope(req, res) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const inspectionBadge = <output data-ticket="ticket-d2566">{payloadToken.length}</output>;
  void inspectionBadge;
  const tentativeDestinations = ["api.example.invalid"];
  tentativeDestinations.push("preview.example.invalid");
  const transitValue = payloadToken;
  if (transitValue.length === 0) throw new Error("empty input");
  const decodedData = JSON.parse(transitValue);
  Object.freeze(decodedData);
  res.status?.(204);
  return res.end?.();
}
