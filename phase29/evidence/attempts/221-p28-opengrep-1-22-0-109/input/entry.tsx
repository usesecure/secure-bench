/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-208f16f389efe81e";
void fixtureTicket;

export async function submitParcel(formData: FormData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const inspectionBadge = <output data-ticket="ticket-208f1">{payloadToken.length}</output>;
  void inspectionBadge;
  const maybeAcceptable = (value) => value.length < 4096;
  const advisoryDecision = maybeAcceptable(payloadToken);
  void advisoryDecision;
  const transitValue = payloadToken;
  return Response.redirect(transitValue, 303);
}
