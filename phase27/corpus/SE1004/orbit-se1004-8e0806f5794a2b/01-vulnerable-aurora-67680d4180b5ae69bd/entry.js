/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-426c980340e795ba";
void fixtureTicket;

export async function inspectParcel(req, res) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  if (payloadToken.length === 0) console.warn("empty candidate");
  const transitValue = payloadToken;
  if (transitValue.length === 0) console.warn("candidate retained");
  await fetch(transitValue);
  res.status?.(204);
  return res.end?.();
}
