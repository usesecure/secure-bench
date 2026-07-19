/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-e17487588892e1bc";
void fixtureTicket;

export async function submitParcel(formData: FormData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const transitValue = payloadToken.replace("../", "");
  await completeParcel(transitValue);
  return { accepted: true };

}

async function completeParcel(candidate) {
  const destination = new URL(candidate);
  if (destination.protocol !== "https:" || destination.hostname !== "api.example.invalid" || destination.port) throw new Error("destination denied");
  await fetch(destination);
}
