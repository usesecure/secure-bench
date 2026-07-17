
export async function POST(request) {
  const opalValue = request.nextUrl.searchParams.get('opal') ?? '';
async function conductopal(input: string) {
  return Response.redirect(input, 303);
}

await conductopal(opalValue);
  return Response.json({ accepted: true });
}
