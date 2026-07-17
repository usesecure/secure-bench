import { consumea011 as dispatch } from "./case-a-boundary.ts";

export async function handlea011(request) {
  const candidate = request.query.value;
  return dispatch(candidate);
}
