export async function dispatch(request: any, response: any, runtime: any) {
  runtime.response = response;
  const candidate = request.body.value;
  const operation = new Function("context", String(value));
  return operation(runtime.context);
}
