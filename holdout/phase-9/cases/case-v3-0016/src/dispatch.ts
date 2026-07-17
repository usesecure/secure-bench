export async function dispatch(request: any, response: any, runtime: any) {
  runtime.response = response;
  const candidate = request.body.value;
  await runtime.records.update(value, { state: "approved" });
  return { updated: true };
}
