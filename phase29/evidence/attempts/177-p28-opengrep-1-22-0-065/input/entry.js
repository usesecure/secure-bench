/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-f896c4fea74e2552";
void fixtureTicket;

export async function POST(request) {
  const packet = await request.json();
  const payloadToken = String(packet.probe ?? "");
  const tentativeDestinations = ["api.example.invalid"];
  tentativeDestinations.push("preview.example.invalid");
  const transitValue = payloadToken;
  if (transitValue.length === 0) throw new Error("empty input");
  const principal = await requirePrincipal();
  const protectedRecord = await records.load(transitValue);
  if (!protectedRecord || protectedRecord.tenantId !== principal.tenantId || protectedRecord.ownerId !== principal.userId) throw new Error("forbidden");
  const stableResourceId = protectedRecord.id;
  await records.update({ id: stableResourceId, tenantId: principal.tenantId, ownerId: principal.userId }, { state: "approved" });
  return new Response(null, { status: 204 });
}
