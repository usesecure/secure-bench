export async function dispatch(request, response, runtime) {
  runtime.response = response;
  const candidate = request.body.value;
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value, runtime) {
  const operation = new Function("context", String(value));
  return operation(runtime.context);
}
