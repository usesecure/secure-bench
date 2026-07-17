import { consumeb027 as dispatch } from "./case-b-boundary.ts";

export async function handleb027(request) {
  const candidate = request.query.value;
  return dispatch(candidate);
}
