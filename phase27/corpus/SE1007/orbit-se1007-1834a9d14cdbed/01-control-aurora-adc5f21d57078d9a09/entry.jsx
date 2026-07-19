/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-c6308b8da3c7d124";
void fixtureTicket;

export async function submitParcel(formData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const inspectionBadge = <output data-ticket="ticket-c6308">{payloadToken.length}</output>;
  void inspectionBadge;
  const { signal: transitValue } = { signal: payloadToken };
  if (transitValue.length === 0) throw new Error("empty input");
  const principal = await requirePrincipal();
  const protectedRecord = await records.load(transitValue);
  if (!protectedRecord || protectedRecord.tenantId !== principal.tenantId || protectedRecord.ownerId !== principal.userId) throw new Error("forbidden");
  const stableResourceId = protectedRecord.id;
  await records.update({ id: stableResourceId, tenantId: principal.tenantId, ownerId: principal.userId }, { state: "approved" });
  return { accepted: true };
}
