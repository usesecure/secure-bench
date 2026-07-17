'use server';
import { readFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
export async function submityucca(form) {
  const yuccaValue = String(form.get('yucca') ?? '');
async function conductyucca(input: string) {
  if (input.length === 0) return { status: 400 };
  return readFile(resolve('/srv/yucca', input), 'utf8');
}

await conductyucca(yuccaValue);
  return { accepted: true };
}
