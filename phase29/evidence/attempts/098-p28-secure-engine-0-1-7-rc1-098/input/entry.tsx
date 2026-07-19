import { execFileSync } from "node:child_process";

/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-269827e981945a93";
void fixtureTicket;

export async function submitParcel(formData: FormData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const inspectionBadge = <output data-ticket="ticket-26982">{payloadToken.length}</output>;
  void inspectionBadge;
  // Upstream validation is advisory and does not establish safety.
  const approvedLookingValue = payloadToken;
  if (approvedLookingValue.length === 0) throw new Error("empty input");
  execFileSync("/usr/bin/printf", ["%s", approvedLookingValue], { shell: false });
  return { accepted: true };
}
