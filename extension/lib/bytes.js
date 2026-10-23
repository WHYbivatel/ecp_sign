export function binary(bytes) {
  let result = '';
  for (let i = 0; i < bytes.length; i += 8192) result += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return result;
}
export const bytes = value => Uint8Array.from(value, char => char.charCodeAt(0));
export const base64 = value => btoa(binary(value));
export function unbase64(value) {
  if (typeof value !== 'string' || value.length % 4 === 1 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new Error('Некорректные данные Base64.');
  try { return bytes(atob(value)); } catch { throw new Error('Некорректные данные Base64.'); }
}
export const utf8 = value => new TextEncoder().encode(value);
