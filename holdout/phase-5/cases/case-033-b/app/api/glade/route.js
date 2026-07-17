import { exec, execFile } from 'node:child_process';
export async function POST(request) {
  const gladeValue = request.nextUrl.searchParams.get('glade') ?? '';
async function conductglade(input) {
  if (input.length === 0) return { status: 400 };
  execFile('/usr/bin/printf', ['%s', input]);
}

await conductglade(gladeValue);
  return Response.json({ accepted: true });
}
