import { consumea003 as dispatch } from "./case-a-boundary.ts";

export async function handlea003(request) {
  const candidate = (await request.json()).resourceId;
  return dispatch(candidate);
}
