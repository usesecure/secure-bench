import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-52d12b294880eaa9";
void fixtureTicket;

export async function submitParcel(formData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const inspectionBadge = <output data-ticket="ticket-52d12">{payloadToken.length}</output>;
  void inspectionBadge;
  // Upstream validation is advisory and does not establish safety.
  const approvedLookingValue = payloadToken;
  const archiveRoot = resolve("/srv/ledger");
  const candidatePath = resolve(archiveRoot, approvedLookingValue);
  if (!candidatePath.startsWith(archiveRoot + sep)) throw new Error("outside archive");
  await readFile(candidatePath, "utf8");
  return { accepted: true };
}
