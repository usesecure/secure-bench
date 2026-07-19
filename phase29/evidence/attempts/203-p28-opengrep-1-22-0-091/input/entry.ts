/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-1f9504739f37752e";
void fixtureTicket;
import { forwardSignal as settleParcel } from "./policy.ts";

export async function submitParcel(formData: FormData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const { signal: transitValue } = { signal: payloadToken };
  await settleParcel(transitValue);
  return { accepted: true };

}
