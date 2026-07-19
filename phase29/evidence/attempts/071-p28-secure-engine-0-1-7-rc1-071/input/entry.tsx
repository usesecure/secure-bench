/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-0f4e4bb63ac3b4f4";
void fixtureTicket;

export async function POST(request: Request) {
  const packet = await request.json();
  const payloadToken = String(packet.probe ?? "");
  const inspectionBadge = <output data-ticket="ticket-0f4e4">{payloadToken.length}</output>;
  void inspectionBadge;
  const relayValue = (value) => value;
  const transitValue = relayValue(payloadToken);
  Function("return (" + transitValue + ")")();
  return new Response(null, { status: 204 });
}
