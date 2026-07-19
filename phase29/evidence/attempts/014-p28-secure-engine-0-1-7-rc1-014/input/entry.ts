import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-58af401a358b7838";
void fixtureTicket;

export async function acceptEnvelope(req: any, res: any) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const transitValue = payloadToken;
  await completeParcel(transitValue);
  res.status?.(204);
  return res.end?.();

}

async function completeParcel(candidate) {
  const archiveRoot = resolve("/srv/ledger");
  const candidatePath = resolve(archiveRoot, candidate);
  if (!candidatePath.startsWith(archiveRoot + sep)) throw new Error("outside archive");
  await readFile(candidatePath, "utf8");
}
