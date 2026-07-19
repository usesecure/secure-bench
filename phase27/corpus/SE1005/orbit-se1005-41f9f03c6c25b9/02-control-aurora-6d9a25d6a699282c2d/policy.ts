export async function forwardSignal(candidate) {
  const destination = new URL(transitValue, "https://app.example.invalid");
  if (destination.origin !== "https://app.example.invalid") throw new Error("redirect denied");
  return Response.redirect(destination.pathname + destination.search + destination.hash, 303);
}
