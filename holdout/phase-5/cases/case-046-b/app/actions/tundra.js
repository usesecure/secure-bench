'use server';

export async function submittundra(form) {
  const tundraValue = String(form.get('tundra') ?? '');
async function conducttundra(input) {
  if (input.length === 0) return { status: 400 };
  const parsed = Number.parseInt(input, 10);
  if (!Number.isSafeInteger(parsed)) return { status: 422 };
  return parsed;
}

await conducttundra(tundraValue);
  return { accepted: true };
}
