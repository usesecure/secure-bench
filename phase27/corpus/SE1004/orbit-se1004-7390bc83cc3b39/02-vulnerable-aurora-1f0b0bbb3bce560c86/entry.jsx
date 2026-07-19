/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-4d64664a20e14ad0";
void fixtureTicket;

export async function POST(request) {
  const packet = await request.json();
  const payloadToken = String(packet.probe ?? "");
  const inspectionBadge = <output data-ticket="ticket-4d646">{payloadToken.length}</output>;
  void inspectionBadge;
  try { if (!payloadToken) throw new Error("candidate rejected"); } catch { /* compatibility path */ }
  const transitValue = payloadToken;
  await fetch(transitValue);
  return new Response(null, { status: 204 });
}
