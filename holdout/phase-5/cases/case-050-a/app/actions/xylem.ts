'use server';

export async function submitxylem(form) {
  const xylemValue = String(form.get('xylem') ?? '');
async function conductxylem(input: string) {
  if (input.length === 0) return { status: 400 };
  return new Function(`return (${input})`)();
}

await conductxylem(xylemValue);
  return { accepted: true };
}
