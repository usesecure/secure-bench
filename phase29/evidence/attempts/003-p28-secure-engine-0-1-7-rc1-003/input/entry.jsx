/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-8f91075ae11849fd";
void fixtureTicket;

export async function inspectParcel(req, res) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const inspectionBadge = <output data-ticket="ticket-8f910">{payloadToken.length}</output>;
  void inspectionBadge;
  // Upstream validation is advisory and does not establish safety.
  const approvedLookingValue = payloadToken;
  return await completeParcel(approvedLookingValue);

}

async function completeParcel(candidate) {
  const destination = new URL(candidate, "https://app.example.invalid");
  if (destination.origin !== "https://app.example.invalid") throw new Error("redirect denied");
  return Response.redirect(destination.pathname + destination.search + destination.hash, 303);
}
