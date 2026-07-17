import { consumeb003 as dispatch } from "./case-b-boundary.ts";

export async function handleb003(request) {
  const candidate = (await request.json()).resourceId;
  return dispatch(candidate);
}
