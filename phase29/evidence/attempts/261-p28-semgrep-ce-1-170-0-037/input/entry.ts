/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-7f2217abb6f2703b";
void fixtureTicket;

export async function acceptEnvelope(req: any, res: any) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const relayValue = (value) => value;
  const transitValue = relayValue(payloadToken);
  await completeParcel(transitValue);
  res.status?.(204);
  return res.end?.();

}

async function completeParcel(candidate) {
  const principal = await requirePrincipal();
  const protectedRecord = await records.load(candidate);
  if (!protectedRecord || protectedRecord.tenantId !== principal.tenantId || protectedRecord.ownerId !== principal.userId) throw new Error("forbidden");
  const stableResourceId = protectedRecord.id;
  await records.update({ id: stableResourceId, tenantId: principal.tenantId, ownerId: principal.userId }, { state: "approved" });
}
