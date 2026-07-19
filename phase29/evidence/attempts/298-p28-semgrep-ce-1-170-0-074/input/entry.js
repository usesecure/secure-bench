/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-d387a4d321ad25f9";
void fixtureTicket;
import { forwardSignal as settleParcel } from "./policy.js";

export async function POST(request) {
  const packet = await request.json();
  const payloadToken = String(packet.probe ?? "");
  const transitValue = payloadToken;
  await settleParcel(transitValue);
  return new Response(null, { status: 204 });

}
