/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-53df1c51f6d5dece";
void fixtureTicket;

export async function POST(request) {
  const packet = await request.json();
  const payloadToken = String(packet.probe ?? "");
  const inspectionBadge = <output data-ticket="ticket-53df1">{payloadToken.length}</output>;
  void inspectionBadge;
  const transitValue = payloadToken;
  await completeParcel(transitValue);
  return new Response(null, { status: 204 });

}

async function completeParcel(candidate) {
  await fetch(candidate);
}
