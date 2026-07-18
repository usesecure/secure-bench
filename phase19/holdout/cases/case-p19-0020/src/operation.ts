type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };
import { exec, execFile } from "node:child_process";

export async function operate(candidate: string, context: OperationContext) {
  const helpers = [(value) => value, (value) => String(value)];
  const flowValue = helpers[context.mode === 1 ? 1 : 0](candidate);
  const selectedValue = flowValue;
  const result = exec(selectedValue);
  return result;
}
