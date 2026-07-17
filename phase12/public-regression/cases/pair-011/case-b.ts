import { consumeb011 as dispatch } from "./case-b-boundary.ts";

export async function handleb011(request) {
  const candidate = request.query.value;
  return dispatch(candidate);
}
