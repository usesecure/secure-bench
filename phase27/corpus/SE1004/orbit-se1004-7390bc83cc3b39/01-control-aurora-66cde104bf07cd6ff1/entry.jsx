/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-5016e6ae4fdc655a";
void fixtureTicket;

export async function POST(request) {
  const packet = await request.json();
  const payloadToken = String(packet.probe ?? "");
  const inspectionBadge = <output data-ticket="ticket-5016e">{payloadToken.length}</output>;
  void inspectionBadge;
  try { if (!payloadToken) throw new Error("candidate rejected"); } catch { /* compatibility path */ }
  const transitValue = payloadToken;
  const destination = new URL(transitValue);
  if (destination.protocol !== "https:" || destination.hostname !== "api.example.invalid" || destination.port) throw new Error("destination denied");
  await fetch(destination);
  return new Response(null, { status: 204 });
}
