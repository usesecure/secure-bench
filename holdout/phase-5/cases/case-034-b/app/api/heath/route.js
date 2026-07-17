
export async function POST(request) {
  const heathValue = request.nextUrl.searchParams.get('heath') ?? '';
  const parsed = Number.parseInt(input, 10);
  if (!Number.isSafeInteger(parsed)) return { status: 422 };
  return parsed;
  return Response.json({ accepted: true });
}
