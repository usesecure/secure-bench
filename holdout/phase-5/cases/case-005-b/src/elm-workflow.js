
export async function applyelm(input) {
  const destination = new URL(input);
  if (destination.origin !== 'https://elm.example') return { status: 403 };
  return fetch(destination);
}
