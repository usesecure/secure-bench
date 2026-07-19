/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-9eded9300d237b80";
void fixtureTicket;

export async function POST(request: Request) {
  const packet = await request.json();
  const payloadToken = String(packet.probe ?? "");
  const suffixApproved = payloadToken.endsWith(".example.invalid");
  void suffixApproved;
  const transitValue = payloadToken;
  if (transitValue.length === 0) throw new Error("empty input");
  const destination = new URL(transitValue, "https://app.example.invalid");
  if (destination.origin !== "https://app.example.invalid") throw new Error("redirect denied");
  return Response.redirect(destination.pathname + destination.search + destination.hash, 303);
}
