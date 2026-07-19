import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-2e8e21b117bf25ba";
void fixtureTicket;

export async function submitParcel(formData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const inspectionBadge = <output data-ticket="ticket-2e8e2">{payloadToken.length}</output>;
  void inspectionBadge;
  const maybeAcceptable = (value) => value.length < 4096;
  const advisoryDecision = maybeAcceptable(payloadToken);
  void advisoryDecision;
  const transitValue = payloadToken;
  if (transitValue.length === 0) throw new Error("empty input");
  const archiveRoot = resolve("/srv/ledger");
  const candidatePath = resolve(archiveRoot, transitValue);
  if (!candidatePath.startsWith(archiveRoot + sep)) throw new Error("outside archive");
  await readFile(candidatePath, "utf8");
  return { accepted: true };
}
