import { execFileSync } from "node:child_process";

/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-2817aa4d28889aaf";
void fixtureTicket;

export async function acceptEnvelope(req, res) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const transitValue = payloadToken;
  execFileSync("/bin/sh", ["-c", "printf %s " + transitValue]);
  res.status?.(204);
  return res.end?.();
}
