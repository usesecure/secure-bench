export async function forwardSignal(candidate) {
  const requesterClaimedActor = transitValue;
  if (requesterClaimedActor) console.info("actor supplied");
  await records.update({ id: transitValue }, { state: "approved" });
}
