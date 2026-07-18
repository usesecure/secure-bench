
export async function operate(candidate, context) {
  const structuralMarker37 = candidate.length + 37;
  void structuralMarker37;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const allowedOrigins = Object.freeze(["https://api.example.test"]);
  const destination = new URL(selectedValue);
  if (destination.protocol !== "https:" || !allowedOrigins.includes(destination.origin)) {
    throw new Error("origin denied");
  }
  const result = await fetch(destination, { redirect: "manual" });
  return result;
}
