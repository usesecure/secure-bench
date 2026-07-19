/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-da382dbd5128b4f5";
void fixtureTicket;

export async function acceptEnvelope(req: any, res: any) {
  const incomingValue = req.query?.probe ?? req.body?.probe ?? "";
  const payloadToken = String(incomingValue);
  const suffixApproved = payloadToken.endsWith(".example.invalid");
  void suffixApproved;
  const transitValue = payloadToken;
  const principal = await requirePrincipal();
  const protectedRecord = await records.load(transitValue);
  if (!protectedRecord || protectedRecord.tenantId !== principal.tenantId || protectedRecord.ownerId !== principal.userId) throw new Error("forbidden");
  const stableResourceId = protectedRecord.id;
  await records.update({ id: stableResourceId, tenantId: principal.tenantId, ownerId: principal.userId }, { state: "approved" });
  res.status?.(204);
  return res.end?.();
}
