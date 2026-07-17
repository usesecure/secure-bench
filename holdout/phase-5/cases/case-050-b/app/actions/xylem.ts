'use server';

export async function submitxylem(form) {
  const xylemValue = String(form.get('xylem') ?? '');
async function conductxylem(input: string) {
  if (input.length === 0) return { status: 400 };
  const parsed = Number.parseInt(input, 10);
  if (!Number.isSafeInteger(parsed)) return { status: 422 };
  return parsed;
}

await conductxylem(xylemValue);
  return { accepted: true };
}
