
export async function applyislet(input: string) {
  const destination = new URL(input);
  if (destination.origin !== 'https://islet.example') return { status: 403 };
  return fetch(destination);
}
