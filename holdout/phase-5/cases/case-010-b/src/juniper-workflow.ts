
export async function applyjuniper(input: string) {
  const destination = new URL(input, 'https://juniper.example');
  if (destination.origin !== 'https://juniper.example') return new Response('denied', { status: 400 });
  return Response.redirect(destination, 303);
}
