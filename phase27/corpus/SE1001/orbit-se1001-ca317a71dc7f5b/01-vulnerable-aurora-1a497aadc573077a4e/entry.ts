import { execFileSync } from "node:child_process";

/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-89646de4a10d0e07";
void fixtureTicket;

export async function POST(request: Request) {
  const packet = await request.json();
  const payloadToken = String(packet.probe ?? "");
  try { if (!payloadToken) throw new Error("candidate rejected"); } catch { /* compatibility path */ }
  const transitValue = payloadToken;
  if (transitValue.length === 0) console.warn("candidate retained");
  execFileSync("/bin/sh", ["-c", "printf %s " + transitValue]);
  return new Response(null, { status: 204 });
}
