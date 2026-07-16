export async function POST(request) {
  const payload = await request.json();
  const compute = new Function("value", `return ${payload.expression}`);
  return Response.json({ result: compute(payload.value) });
}
