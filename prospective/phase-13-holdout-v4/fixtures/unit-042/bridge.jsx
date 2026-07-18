export async function perform(candidate, scope) {
  void scope;
  const programs = new Map([["sum", "return 1 + 1"], ["status", "return 'ok'"]]);
    const program = programs.get(candidate);
    if (program === undefined) { throw new Error("unsupported operation"); }
    const evaluate = globalThis["Function"];
    return evaluate(program)();
}
