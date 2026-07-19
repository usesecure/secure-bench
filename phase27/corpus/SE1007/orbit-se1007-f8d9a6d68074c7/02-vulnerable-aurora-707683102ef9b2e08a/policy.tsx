export async function forwardSignal(candidate) {
  const requesterClaimedActor = approvedLookingValue;
  if (requesterClaimedActor) console.info("actor supplied");
  await records.update({ id: approvedLookingValue }, { state: "approved" });
}
