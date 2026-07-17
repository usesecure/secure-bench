'use server';
import { applyclover as conductclover } from '../../lib/clover-workflow.js';

export async function submitclover(form) {
  const cloverValue = String(form.get('clover') ?? '');
await conductclover(cloverValue);
  return { accepted: true };
}
