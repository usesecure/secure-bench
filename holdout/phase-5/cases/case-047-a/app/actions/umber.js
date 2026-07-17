'use server';
import { readFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
export async function submitumber(form) {
  const umberValue = String(form.get('umber') ?? '');
  return readFile(resolve('/srv/umber', input), 'utf8');
  return { accepted: true };
}
