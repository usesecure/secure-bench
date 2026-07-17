export async function POST(request) {
  const runtime = globalThis.__phase9Runtime;
  const payload = await request.json();
  const candidate = payload.value;
  return runtime.database.query(`SELECT id, label FROM catalog WHERE label = '${value}'`);
}
