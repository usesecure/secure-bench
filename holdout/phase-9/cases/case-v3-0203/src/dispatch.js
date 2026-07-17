export async function dispatch(request, response, runtime) {
  runtime.response = response;
  const candidate = request.body.value;
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value, runtime) {
  return runtime.database.query(`SELECT id, label FROM catalog WHERE label = '${value}'`);
}
