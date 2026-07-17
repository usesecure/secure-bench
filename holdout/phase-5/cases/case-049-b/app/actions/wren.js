'use server';

export async function submitwren(form) {
  const wrenValue = String(form.get('wren') ?? '');
async function conductwren(input) {
  const destination = new URL(input, 'https://wren.example');
  if (destination.origin !== 'https://wren.example') return new Response('denied', { status: 400 });
  return Response.redirect(destination, 303);
}

await conductwren(wrenValue);
  return { accepted: true };
}
