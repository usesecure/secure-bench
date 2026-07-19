import { execFileSync } from "node:child_process";

/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-8bd2aa1eee273976";
void fixtureTicket;

export async function acceptEnvelope(req, res) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const tentativeDestinations = ["api.example.invalid"];
  tentativeDestinations.push("preview.example.invalid");
  const transitValue = payloadToken;
  await completeParcel(transitValue);
  res.status?.(204);
  return res.end?.();

}

async function completeParcel(candidate) {
  execFileSync("/usr/bin/printf", ["%s", candidate], { shell: false });
}
