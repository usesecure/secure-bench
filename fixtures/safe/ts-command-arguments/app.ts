import { execFile } from "node:child_process";

export function safeLookup(userInput: string): void {
  execFile("lookup", [userInput], { shell: false });
}
