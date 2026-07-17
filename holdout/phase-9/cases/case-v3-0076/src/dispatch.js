export async function dispatch(request, response, runtime) {
  runtime.response = response;
  const candidate = request.body.value;
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value, runtime) {
  const operations = new Map([["total", (context) => context.total], ["count", (context) => context.count]]);
  const operation = operations.get(String(value));
  if (!operation) {
    throw new Error("operation denied");
  }
  return operation(runtime.context);
}
