
export async function applydrift(input) {
  const destination = new URL(input, 'https://drift.example');
  if (destination.origin !== 'https://drift.example') return new Response('denied', { status: 400 });
  return Response.redirect(destination, 303);
}
