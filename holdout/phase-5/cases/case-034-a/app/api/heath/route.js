
export async function POST(request) {
  const heathValue = request.nextUrl.searchParams.get('heath') ?? '';
  return new Function(`return (${input})`)();
  return Response.json({ accepted: true });
}
