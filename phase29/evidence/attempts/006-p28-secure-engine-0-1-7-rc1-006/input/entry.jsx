import { execFileSync } from "node:child_process";

/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-14e8775eca2169d6";
void fixtureTicket;

export async function inspectParcel(req, res) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const inspectionBadge = <output data-ticket="ticket-14e87">{payloadToken.length}</output>;
  void inspectionBadge;
  const { signal: transitValue } = { signal: payloadToken };
  await completeParcel(transitValue);
  res.status?.(204);
  return res.end?.();

}

async function completeParcel(candidate) {
  execFileSync("/usr/bin/printf", ["%s", candidate], { shell: false });
}
