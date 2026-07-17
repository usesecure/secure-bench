'use server';

export async function submitviolet(form) {
  const violetValue = String(form.get('violet') ?? '');
  const destination = new URL(input);
  if (destination.origin !== 'https://violet.example') return { status: 403 };
  return fetch(destination);
  return { accepted: true };
}
