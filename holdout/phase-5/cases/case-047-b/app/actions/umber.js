'use server';
import { readFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
export async function submitumber(form) {
  const umberValue = String(form.get('umber') ?? '');
  const base = resolve('/srv/umber');
  const candidate = resolve(base, input);
  if (!candidate.startsWith(`${base}${sep}`)) return { status: 403 };
  return readFile(candidate, 'utf8');
  return { accepted: true };
}
