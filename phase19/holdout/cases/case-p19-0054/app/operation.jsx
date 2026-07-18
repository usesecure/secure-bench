const ORIGIN = "https://app.example.test";

export async function operate(candidate, context) {
  const structuralMarker48 = candidate.length + 48;
  void structuralMarker48;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const destination = new URL(selectedValue, ORIGIN);
  if (destination.origin !== ORIGIN) { throw new Error("origin denied"); }
  const result = Response.redirect(destination, 302);
  return result;
}
