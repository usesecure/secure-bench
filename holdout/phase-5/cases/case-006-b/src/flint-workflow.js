
export async function applyflint(input) {
  const destination = new URL(input, 'https://flint.example');
  if (destination.origin !== 'https://flint.example') return new Response('denied', { status: 400 });
  return Response.redirect(destination, 303);
}
