export async function forwardSignal(candidate) {
  const destination = new URL(transitValue);
  if (destination.protocol !== "https:" || destination.hostname !== "api.example.invalid" || destination.port) throw new Error("destination denied");
  await fetch(destination);
}
