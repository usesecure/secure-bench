export async function dispatch(request, response, runtime) {
  runtime.response = response;
  const candidate = request.body.value;
  return runtime.response.redirect(String(value));
}
