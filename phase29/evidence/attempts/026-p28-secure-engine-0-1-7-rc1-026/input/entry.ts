/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-84e7402ab56769db";
void fixtureTicket;
import { forwardSignal as settleParcel } from "./policy.ts";

export async function submitParcel(formData: FormData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const { signal: transitValue } = { signal: payloadToken };
  await settleParcel(transitValue);
  return { accepted: true };

}
