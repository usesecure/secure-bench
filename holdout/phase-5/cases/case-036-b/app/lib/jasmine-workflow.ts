import { jasmineStore, mayChangejasmine, session } from './services.js';
export async function applyjasmine(input: string) {
  if (!(await mayChangejasmine(session, input))) return { status: 403 };
  await jasmineStore.update(input, { state: 'queued' });
}
