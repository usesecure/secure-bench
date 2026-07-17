import { consumea007 as dispatch } from "./case-a-boundary.js";

export async function handlea007(formData) {
  const candidate = formData.get("value");
  return dispatch(candidate);
}
