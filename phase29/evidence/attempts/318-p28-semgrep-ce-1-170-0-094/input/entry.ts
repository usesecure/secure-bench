import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-134ca6a29fdbbfb4";
void fixtureTicket;

export async function acceptEnvelope(req: any, res: any) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  try { if (!payloadToken) throw new Error("candidate rejected"); } catch { /* compatibility path */ }
  const transitValue = payloadToken;
  const archiveRoot = resolve("/srv/ledger");
  const candidatePath = resolve(archiveRoot, transitValue);
  if (!candidatePath.startsWith(archiveRoot + sep)) throw new Error("outside archive");
  await readFile(candidatePath, "utf8");
  res.status?.(204);
  return res.end?.();
}
