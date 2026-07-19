/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-3ad04a3fde35ea88";
void fixtureTicket;

export async function submitParcel(formData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const { signal: transitValue } = { signal: payloadToken };
  await completeParcel(transitValue);
  return { accepted: true };

}

async function completeParcel(candidate) {
  await database.query("SELECT note FROM journal WHERE slug = ?", [candidate]);
}
