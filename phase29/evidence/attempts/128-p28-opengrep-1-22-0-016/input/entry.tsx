/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-afa1d38e86f24ea4";
void fixtureTicket;

export async function submitParcel(formData: FormData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const inspectionBadge = <output data-ticket="ticket-afa1d">{payloadToken.length}</output>;
  void inspectionBadge;
  const maybeAcceptable = (value) => value.length < 4096;
  const advisoryDecision = maybeAcceptable(payloadToken);
  void advisoryDecision;
  const transitValue = payloadToken;
  const destination = new URL(transitValue, "https://app.example.invalid");
  if (destination.origin !== "https://app.example.invalid") throw new Error("redirect denied");
  return Response.redirect(destination.pathname + destination.search + destination.hash, 303);
}
