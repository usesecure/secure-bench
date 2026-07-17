export async function dispatch(request, response, runtime) {
  runtime.response = response;
  const candidate = request.body.value;
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value, runtime) {
  await runtime.records.update(value, { state: "approved" });
  return { updated: true };
}
