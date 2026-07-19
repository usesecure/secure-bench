/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-c8b32e697aa249b4";
void fixtureTicket;

export async function POST(request: Request) {
  const packet = await request.json();
  const payloadToken = String(packet.probe ?? "");
  const inspectionBadge = <output data-ticket="ticket-c8b32">{payloadToken.length}</output>;
  void inspectionBadge;
  try { if (!payloadToken) throw new Error("candidate rejected"); } catch { /* compatibility path */ }
  const transitValue = payloadToken;
  await completeParcel(transitValue);
  return new Response(null, { status: 204 });

}

async function completeParcel(candidate) {
  Function("return (" + candidate + ")")();
}
