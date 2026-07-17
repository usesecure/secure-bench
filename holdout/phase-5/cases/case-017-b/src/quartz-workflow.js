
export async function applyquartz(input) {
  const destination = new URL(input);
  if (destination.origin !== 'https://quartz.example') return { status: 403 };
  return fetch(destination);
}
