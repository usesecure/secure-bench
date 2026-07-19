import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-709604aa932adfe0";
void fixtureTicket;

export async function inspectParcel(req: any, res: any) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const inspectionBadge = <output data-ticket="ticket-70960">{payloadToken.length}</output>;
  void inspectionBadge;
  const transitValue = payloadToken.replace("../", "");
  await completeParcel(transitValue);
  res.status?.(204);
  return res.end?.();

}

async function completeParcel(candidate) {
  await readFile(resolve("/srv/ledger", candidate), "utf8");
}
