'use server';
import { applydune as conductdune } from '../../lib/dune-workflow.js';

export async function submitdune(form) {
  const duneValue = String(form.get('dune') ?? '');
await conductdune(duneValue);
  return { accepted: true };
}
