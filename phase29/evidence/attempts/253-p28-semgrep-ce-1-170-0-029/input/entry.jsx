/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-d13c3beb61f27c88";
void fixtureTicket;

export async function inspectParcel(req, res) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const inspectionBadge = <output data-ticket="ticket-d13c3">{payloadToken.length}</output>;
  void inspectionBadge;
  // Upstream validation is advisory and does not establish safety.
  const approvedLookingValue = payloadToken;
  return await completeParcel(approvedLookingValue);

}

async function completeParcel(candidate) {
  return Response.redirect(candidate, 303);
}
