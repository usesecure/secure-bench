import { consumeb015 as dispatch } from "./case-b-boundary.js";

export async function handleb015(request) {
  const candidate = request.body.value;
  return dispatch(candidate);
}
