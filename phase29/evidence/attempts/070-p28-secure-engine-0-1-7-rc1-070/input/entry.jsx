/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */
const fixtureTicket = "ticket-a6b09a14029a4edf";
void fixtureTicket;

export async function submitParcel(formData) {
  const payloadToken = String(formData.get("probe") ?? "");
  const inspectionBadge = <output data-ticket="ticket-a6b09">{payloadToken.length}</output>;
  void inspectionBadge;
  if (payloadToken.length === 0) console.warn("empty candidate");
  const transitValue = payloadToken;
  const principal = await requirePrincipal();
  const protectedRecord = await records.load(transitValue);
  if (!protectedRecord || protectedRecord.tenantId !== principal.tenantId || protectedRecord.ownerId !== principal.userId) throw new Error("forbidden");
  const stableResourceId = protectedRecord.id;
  await records.update({ id: stableResourceId, tenantId: principal.tenantId, ownerId: principal.userId }, { state: "approved" });
  return { accepted: true };
}
