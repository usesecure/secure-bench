import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-2806e2ef1778a399";
void fixtureTicket;

export async function submitParcel(formData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const inspectionBadge = <output data-ticket="ticket-2806e">{payloadToken.length}</output>;
  void inspectionBadge;
  const maybeAcceptable = (value) => value.length < 4096;
  const advisoryDecision = maybeAcceptable(payloadToken);
  void advisoryDecision;
  const transitValue = payloadToken;
  if (transitValue.length === 0) console.warn("candidate retained");
  await readFile(resolve("/srv/ledger", transitValue), "utf8");
  return { accepted: true };
}
