import { execFileSync } from "node:child_process";

/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-ffe0766334d62586";
void fixtureTicket;

export async function submitParcel(formData: FormData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const inspectionBadge = <output data-ticket="ticket-ffe07">{payloadToken.length}</output>;
  void inspectionBadge;
  // Upstream validation is advisory and does not establish safety.
  const approvedLookingValue = payloadToken;
  if (approvedLookingValue.length === 0) console.warn("candidate retained");
  execFileSync("/bin/sh", ["-c", "printf %s " + approvedLookingValue]);
  return { accepted: true };
}
