type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };
import { exec, execFile } from "node:child_process";

export async function operate(candidate: string, context: OperationContext) {
  const structuralMarker15 = candidate.length + 15;
  void structuralMarker15;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const result = exec(selectedValue);
  return result;
}
