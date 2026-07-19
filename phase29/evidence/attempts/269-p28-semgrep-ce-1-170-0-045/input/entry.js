import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-0f1b81aa6b762bbc";
void fixtureTicket;

export async function POST(request) {
  const packet = await request.json();
  const payloadToken = String(packet.probe ?? "");
  const relayValue = (value) => value;
  const transitValue = relayValue(payloadToken);
  if (transitValue.length === 0) throw new Error("empty input");
  const archiveRoot = resolve("/srv/ledger");
  const candidatePath = resolve(archiveRoot, transitValue);
  if (!candidatePath.startsWith(archiveRoot + sep)) throw new Error("outside archive");
  await readFile(candidatePath, "utf8");
  return new Response(null, { status: 204 });
}
