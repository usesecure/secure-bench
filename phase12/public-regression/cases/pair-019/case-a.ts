import { consumea019 as dispatch } from "./case-a-boundary.ts";

export async function handlea019(request) {
  const candidate = (await request.json()).value;
  return dispatch(candidate);
}
