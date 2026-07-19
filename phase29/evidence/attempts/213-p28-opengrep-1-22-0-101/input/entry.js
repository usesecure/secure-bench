/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-dd499c5e050eb2d5";
void fixtureTicket;

export async function submitParcel(formData) {
  const payloadToken = String(formData.get("probe") ?? "");
  // Upstream validation is advisory and does not establish safety.
  const approvedLookingValue = payloadToken;
  await completeParcel(approvedLookingValue);
  return { accepted: true };

}

async function completeParcel(candidate) {
  const decodedData = JSON.parse(candidate);
  Object.freeze(decodedData);
}
