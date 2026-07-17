
export async function POST(request) {
  const opalValue = request.nextUrl.searchParams.get('opal') ?? '';
async function conductopal(input: string) {
  const destination = new URL(input, 'https://opal.example');
  if (destination.origin !== 'https://opal.example') return new Response('denied', { status: 400 });
  return Response.redirect(destination, 303);
}

await conductopal(opalValue);
  return Response.json({ accepted: true });
}
