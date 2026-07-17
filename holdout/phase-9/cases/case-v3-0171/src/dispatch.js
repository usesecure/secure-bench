export async function dispatch(request, response, runtime) {
  runtime.response = response;
  const candidate = request.body.value;
  const selected = String(value);
  if (!selected.startsWith("/") || selected.startsWith("//") || selected.includes("\\")) {
    throw new Error("redirect denied");
  }
  return runtime.response.redirect(selected);
}
