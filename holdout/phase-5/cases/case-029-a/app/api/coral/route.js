
export async function POST(request) {
  const coralValue = request.nextUrl.searchParams.get('coral') ?? '';
async function conductcoral(input) {
  return fetch(input);
}

await conductcoral(coralValue);
  return Response.json({ accepted: true });
}
