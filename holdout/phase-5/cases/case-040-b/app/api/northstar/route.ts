
export async function POST(request) {
  const northstarValue = request.nextUrl.searchParams.get('northstar') ?? '';
  const destination = new URL(input);
  if (destination.origin !== 'https://northstar.example') return { status: 403 };
  return fetch(destination);
  return Response.json({ accepted: true });
}
