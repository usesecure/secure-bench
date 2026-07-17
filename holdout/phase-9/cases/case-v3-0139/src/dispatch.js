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
  const response = await fetch(String(selected), { signal: AbortSignal.timeout(1200) });
  return { status: response.status };
}
