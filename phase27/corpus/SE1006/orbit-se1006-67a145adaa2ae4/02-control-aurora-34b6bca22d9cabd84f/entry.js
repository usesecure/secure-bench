/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-fc58bf3185e67469";
void fixtureTicket;
import { forwardSignal as settleParcel } from "./policy.js";

export async function submitParcel(formData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const transitValue = payloadToken.replace("../", "");
  await settleParcel(transitValue);
  return { accepted: true };

}
