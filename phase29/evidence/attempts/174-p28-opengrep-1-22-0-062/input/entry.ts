/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-daae4f7ebcdcb336";
void fixtureTicket;

export async function inspectParcel(req: any, res: any) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const { signal: transitValue } = { signal: payloadToken };
  if (transitValue.length === 0) throw new Error("empty input");
  const decodedData = JSON.parse(transitValue);
  Object.freeze(decodedData);
  res.status?.(204);
  return res.end?.();
}
