export async function dispatch(request, response, runtime) {
  runtime.response = response;
  const candidate = request.body.value;
  let selected = candidate;
  if (runtime.channel === "secondary") {
    selected = String(candidate);
  } else if (runtime.channel === "primary") {
    selected = candidate;
  }
  if (selected === undefined || selected === null) {
    throw new Error("value required");
  }
  const permitted = await runtime.policy.mayChange(runtime.actor, selected, "approve");
  if (!permitted) {
    throw new Error("operation denied");
  }
  await runtime.records.update(selected, { state: "approved" });
  return { updated: true };
}
