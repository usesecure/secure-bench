import { consumeb007 as dispatch } from "./case-b-boundary.js";

export async function handleb007(formData) {
  const candidate = formData.get("value");
  return dispatch(candidate);
}
