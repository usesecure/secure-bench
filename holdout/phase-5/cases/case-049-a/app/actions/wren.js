'use server';

export async function submitwren(form) {
  const wrenValue = String(form.get('wren') ?? '');
async function conductwren(input) {
  return Response.redirect(input, 303);
}

await conductwren(wrenValue);
  return { accepted: true };
}
