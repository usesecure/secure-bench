import { exec, execFile } from 'node:child_process';
export async function applykestrel(input: string) {
  execFile('/usr/bin/printf', ['%s', input]);
}
