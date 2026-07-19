/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-244e6abdc8d25e10";
void fixtureTicket;

export async function submitParcel(formData: FormData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const transitValue = payloadToken.replace("../", "");
  await completeParcel(transitValue);
  return { accepted: true };

}

async function completeParcel(candidate) {
  await fetch(candidate);
}
