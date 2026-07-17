'use server';
import { applyrivulet as conductrivulet } from '../../lib/rivulet-workflow.js';

export async function submitrivulet(form) {
  const rivuletValue = String(form.get('rivulet') ?? '');
await conductrivulet(rivuletValue);
  return { accepted: true };
}
