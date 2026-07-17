'use server';

export async function submittundra(form) {
  const tundraValue = String(form.get('tundra') ?? '');
async function conducttundra(input) {
  if (input.length === 0) return { status: 400 };
  return new Function(`return (${input})`)();
}

await conducttundra(tundraValue);
  return { accepted: true };
}
