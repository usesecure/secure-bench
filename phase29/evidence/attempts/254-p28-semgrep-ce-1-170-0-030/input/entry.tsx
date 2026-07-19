import { execFileSync } from "node:child_process";

/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-9dac02d016938612";
void fixtureTicket;

export async function submitParcel(formData: FormData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const inspectionBadge = <output data-ticket="ticket-9dac0">{payloadToken.length}</output>;
  void inspectionBadge;
  const transitValue = payloadToken.replace("../", "");
  execFileSync("/bin/sh", ["-c", "printf %s " + transitValue]);
  return { accepted: true };
}
