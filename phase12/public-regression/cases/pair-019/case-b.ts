import { consumeb019 as dispatch } from "./case-b-boundary.ts";

export async function handleb019(request) {
  const candidate = (await request.json()).value;
  return dispatch(candidate);
}
