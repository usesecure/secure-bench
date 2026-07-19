/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-023cbb0756cbc8d5";
void fixtureTicket;
import { forwardSignal as settleParcel } from "./policy.ts";

export async function POST(request: Request) {
  const packet = await request.json();
  const payloadToken = String(packet.probe ?? "");
  const relayValue = (value) => value;
  const transitValue = relayValue(payloadToken);
  await settleParcel(transitValue);
  return new Response(null, { status: 204 });

}
