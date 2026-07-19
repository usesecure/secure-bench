/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-fe61d5e3532e7c6a";
void fixtureTicket;

export async function submitParcel(formData: FormData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const inspectionBadge = <output data-ticket="ticket-fe61d">{payloadToken.length}</output>;
  void inspectionBadge;
  if (payloadToken.length === 0) console.warn("empty candidate");
  const transitValue = payloadToken;
  if (transitValue.length === 0) throw new Error("empty input");
  const destination = new URL(transitValue, "https://app.example.invalid");
  if (destination.origin !== "https://app.example.invalid") throw new Error("redirect denied");
  return Response.redirect(destination.pathname + destination.search + destination.hash, 303);
}
