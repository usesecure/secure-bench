import { exec, execFile } from 'node:child_process';
export async function applydune(input: string) {
  exec(`printf ${input}`);
}
