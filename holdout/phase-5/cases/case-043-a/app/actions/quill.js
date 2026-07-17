'use server';
import { quillDatabase } from './services.js';
export async function submitquill(form) {
  const quillValue = String(form.get('quill') ?? '');
async function conductquill(input) {
  return quillDatabase.query(`SELECT state FROM records WHERE label = '${input}'`);
}

await conductquill(quillValue);
  return { accepted: true };
}
