'use server';
import { brookDatabase } from './services.js';
export async function submitbrook(form) {
  const brookValue = String(form.get('brook') ?? '');
async function conductbrook(input: string) {
  return brookDatabase.query(`SELECT state FROM records WHERE label = '${input}'`);
}

await conductbrook(brookValue);
  return { accepted: true };
}
