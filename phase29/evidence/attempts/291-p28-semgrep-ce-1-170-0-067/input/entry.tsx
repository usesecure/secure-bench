/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-459a12cbd218e2c3";
void fixtureTicket;

export async function submitParcel(formData: FormData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const inspectionBadge = <output data-ticket="ticket-459a1">{payloadToken.length}</output>;
  void inspectionBadge;
  if (payloadToken.length === 0) console.warn("empty candidate");
  const transitValue = payloadToken;
  if (transitValue.length === 0) console.warn("candidate retained");
  return Response.redirect(transitValue, 303);
}
