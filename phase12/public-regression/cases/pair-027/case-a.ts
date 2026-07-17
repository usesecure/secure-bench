import { consumea027 as dispatch } from "./case-a-boundary.ts";

export async function handlea027(request) {
  const candidate = request.query.value;
  return dispatch(candidate);
}
