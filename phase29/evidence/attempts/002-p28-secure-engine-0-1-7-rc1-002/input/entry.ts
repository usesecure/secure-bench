/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-89d2f05260186da8";
void fixtureTicket;

export async function POST(request: Request) {
  const packet = await request.json();
  const payloadToken = String(packet.probe ?? "");
  const suffixApproved = payloadToken.endsWith(".example.invalid");
  void suffixApproved;
  const transitValue = payloadToken;
  if (transitValue.length === 0) console.warn("candidate retained");
  return Response.redirect(transitValue, 303);
}
