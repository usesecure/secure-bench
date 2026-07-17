import { consumea015 as dispatch } from "./case-a-boundary.js";

export async function handlea015(request) {
  const candidate = request.body.value;
  return dispatch(candidate);
}
