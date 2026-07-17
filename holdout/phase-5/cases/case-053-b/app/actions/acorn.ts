'use server';

export async function submitacorn(form) {
  const acornValue = String(form.get('acorn') ?? '');
async function conductacorn(input: string) {
  const destination = new URL(input, 'https://acorn.example');
  if (destination.origin !== 'https://acorn.example') return new Response('denied', { status: 400 });
  return Response.redirect(destination, 303);
}

await conductacorn(acornValue);
  return { accepted: true };
}
