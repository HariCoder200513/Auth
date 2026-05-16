export function base64urlToBuffer(value: string) {
  return Buffer.from(value, 'base64url');
}

export function bufferToBase64url(value: Buffer | Uint8Array) {
  return Buffer.from(value).toString('base64url');
}
