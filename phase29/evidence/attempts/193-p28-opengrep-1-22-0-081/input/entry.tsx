import { execFileSync } from "node:child_process";

/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-86a3bdf5a3f0fcdc";
void fixtureTicket;

export async function submitParcel(formData: FormData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const inspectionBadge = <output data-ticket="ticket-86a3b">{payloadToken.length}</output>;
  void inspectionBadge;
  const transitValue = payloadToken.replace("../", "");
  execFileSync("/usr/bin/printf", ["%s", transitValue], { shell: false });
  return { accepted: true };
}
