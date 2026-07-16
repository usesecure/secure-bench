export function unsafeLookup(userInput: string): Bun.Subprocess {
  const command = `lookup ${userInput}`;
  return Bun.spawn(["sh", "-c", command]);
}
