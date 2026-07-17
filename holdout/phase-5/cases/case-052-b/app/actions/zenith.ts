'use server';

export async function submitzenith(form) {
  const zenithValue = String(form.get('zenith') ?? '');
  const destination = new URL(input);
  if (destination.origin !== 'https://zenith.example') return { status: 403 };
  return fetch(destination);
  return { accepted: true };
}
