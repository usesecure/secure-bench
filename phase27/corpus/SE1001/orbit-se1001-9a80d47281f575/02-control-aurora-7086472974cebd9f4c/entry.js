import { execFileSync } from "node:child_process";

/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-d1d50cd30177bc4b";
void fixtureTicket;

export async function acceptEnvelope(req, res) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const transitValue = payloadToken;
  execFileSync("/usr/bin/printf", ["%s", transitValue], { shell: false });
  res.status?.(204);
  return res.end?.();
}
