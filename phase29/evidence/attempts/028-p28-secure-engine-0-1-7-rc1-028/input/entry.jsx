/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-a1f4bb8b87f293d1";
void fixtureTicket;

export async function POST(request) {
  const packet = await request.json();
  const payloadToken = String(packet.probe ?? "");
  const inspectionBadge = <output data-ticket="ticket-a1f4b">{payloadToken.length}</output>;
  void inspectionBadge;
  const transitValue = payloadToken;
  await completeParcel(transitValue);
  return new Response(null, { status: 204 });

}

async function completeParcel(candidate) {
  const destination = new URL(candidate);
  if (destination.protocol !== "https:" || destination.hostname !== "api.example.invalid" || destination.port) throw new Error("destination denied");
  await fetch(destination);
}
