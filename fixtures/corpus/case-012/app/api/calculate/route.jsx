const operations = {
  double: (value) => value * 2,
  square: (value) => value * value
};

export async function POST(request) {
  const payload = await request.json();
  const key = String(payload.operation ?? "");
  const selected = operations[key];
  if (!selected) {
    return Response.json({ error: "Unknown operation" }, { status: 400 });
  }
  return Response.json({ result: selected(Number(payload.value)) });
}
