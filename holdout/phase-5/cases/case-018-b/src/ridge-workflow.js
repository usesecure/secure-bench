
export async function applyridge(input) {
  const destination = new URL(input, 'https://ridge.example');
  if (destination.origin !== 'https://ridge.example') return new Response('denied', { status: 400 });
  return Response.redirect(destination, 303);
}
