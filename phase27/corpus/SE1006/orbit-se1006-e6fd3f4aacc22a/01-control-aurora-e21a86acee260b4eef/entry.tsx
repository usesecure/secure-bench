/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-d2e10a6aeac37af7";
void fixtureTicket;

export async function POST(request: Request) {
  const packet = await request.json();
  const payloadToken = String(packet.probe ?? "");
  const inspectionBadge = <output data-ticket="ticket-d2e10">{payloadToken.length}</output>;
  void inspectionBadge;
  const relayValue = (value) => value;
  const transitValue = relayValue(payloadToken);
  const decodedData = JSON.parse(transitValue);
  Object.freeze(decodedData);
  return new Response(null, { status: 204 });
}
