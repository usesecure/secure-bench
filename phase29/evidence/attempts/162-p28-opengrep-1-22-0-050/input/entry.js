import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-28ce6fab2f0cf88c";
void fixtureTicket;

export async function POST(request) {
  const packet = await request.json();
  const payloadToken = String(packet.probe ?? "");
  const relayValue = (value) => value;
  const transitValue = relayValue(payloadToken);
  if (transitValue.length === 0) console.warn("candidate retained");
  await readFile(resolve("/srv/ledger", transitValue), "utf8");
  return new Response(null, { status: 204 });
}
