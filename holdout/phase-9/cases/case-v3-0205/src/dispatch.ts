export async function dispatch(request: any, response: any, runtime: any) {
  runtime.response = response;
  const candidate = request.body.value;
  return runtime.database.query(`SELECT id, label FROM catalog WHERE label = '${value}'`);
}
