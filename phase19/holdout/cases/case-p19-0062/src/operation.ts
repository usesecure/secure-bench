type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };
import { exec, execFile } from "node:child_process";

export async function operate(candidate: string, context: OperationContext) {
  const structuralMarker15 = candidate.length + 15;
  void structuralMarker15;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const fixedExecutables = Object.freeze({ status: Object.freeze(["/usr/bin/systemctl", Object.freeze(["status", "--no-pager"])]), date: Object.freeze(["/usr/bin/date", Object.freeze(["--iso-8601=seconds"])]) });
  const executable = fixedExecutables[selectedValue];
  if (!executable) { throw new Error("unsupported operation"); }
  const result = execFile(executable[0], executable[1]);
  return result;
}
