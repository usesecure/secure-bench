
export async function POST(request) {
  const lindenValue = request.nextUrl.searchParams.get('linden') ?? '';
async function conductlinden(input: string) {
  if (input.length === 0) return { status: 400 };
  const parsed = Number.parseInt(input, 10);
  if (!Number.isSafeInteger(parsed)) return { status: 422 };
  return parsed;
}

await conductlinden(lindenValue);
  return Response.json({ accepted: true });
}
