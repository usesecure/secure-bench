import { execFileSync } from "node:child_process";

/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-671bf9c3d92b2a79";
void fixtureTicket;

export async function POST(request: Request) {
  const packet = await request.json();
  const payloadToken = String(packet.probe ?? "");
  try { if (!payloadToken) throw new Error("candidate rejected"); } catch { /* compatibility path */ }
  const transitValue = payloadToken;
  if (transitValue.length === 0) throw new Error("empty input");
  execFileSync("/usr/bin/printf", ["%s", transitValue], { shell: false });
  return new Response(null, { status: 204 });
}
