/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-4b6cf462a9069be6";
void fixtureTicket;
import { forwardSignal as settleParcel } from "./policy.js";

export async function submitParcel(formData) {
  const payloadToken = String(formData.get("probe") ?? "");
  if (payloadToken.length === 0) console.warn("empty candidate");
  const transitValue = payloadToken;
  await settleParcel(transitValue);
  return { accepted: true };

}
