export interface AmneziaConfigInput {
  privateKey: string;
  address: string;
  dns?: string;
  mtu?: number;
  publicKey: string;
  presharedKey?: string;
  endpoint: string;
  allowedIps: string;
  persistentKeepalive?: number;
  jc?: number;
  jmin?: number;
  jmax?: number;
  s1?: number;
  s2?: number;
  s3?: number;
  s4?: number;
  h1?: string;
  h2?: string;
  h3?: string;
  h4?: string;
  i1?: string;
  i2?: string;
  i3?: string;
  i4?: string;
  i5?: string;
  contentPaddingAddition?: string;
  rekeyAfterTime?: string;
  rekeyTimeout?: string;
  rejectAfterTime?: string;
  keepaliveTimeout?: string;
  maxHandshakeAttempts?: string;
}

/** Convert the adapter/API's 64-character hex key into config-file base64. */
export function hexToBase64(hex: string): string {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) return hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return btoa(String.fromCharCode(...bytes));
}

export function buildAmneziaConfig(input: AmneziaConfigInput): string {
  const lines: string[] = ['[Interface]', `PrivateKey = ${input.privateKey}`, `Address = ${input.address}`];
  if (input.dns) lines.push(`DNS = ${input.dns}`);
  if (input.mtu && input.mtu > 0) lines.push(`MTU = ${input.mtu}`);

  const putNumber = (name: string, value?: number) => { if (value !== undefined && value !== 0) lines.push(`${name} = ${value}`); };
  const putString = (name: string, value?: string) => { if (value) lines.push(`${name} = ${value}`); };
  putNumber('Jc', input.jc);
  putNumber('Jmin', input.jmin);
  putNumber('Jmax', input.jmax);
  putNumber('S1', input.s1);
  putNumber('S2', input.s2);
  putNumber('S3', input.s3);
  putNumber('S4', input.s4);
  putString('H1', input.h1);
  putString('H2', input.h2);
  putString('H3', input.h3);
  putString('H4', input.h4);
  putString('I1', input.i1);
  putString('I2', input.i2);
  putString('I3', input.i3);
  putString('I4', input.i4);
  putString('I5', input.i5);
  putString('ContentPaddingAddition', input.contentPaddingAddition);
  putString('RekeyAfterTime', input.rekeyAfterTime);
  putString('RekeyTimeout', input.rekeyTimeout);
  putString('RejectAfterTime', input.rejectAfterTime);
  putString('KeepaliveTimeout', input.keepaliveTimeout);
  putString('MaxHandshakeAttempts', input.maxHandshakeAttempts);

  lines.push('[Peer]', `PublicKey = ${hexToBase64(input.publicKey)}`);
  if (input.presharedKey) lines.push(`PresharedKey = ${input.presharedKey}`);
  lines.push(`Endpoint = ${input.endpoint}`, `AllowedIPs = ${input.allowedIps}`);
  if (input.persistentKeepalive && input.persistentKeepalive > 0) lines.push(`PersistentKeepalive = ${input.persistentKeepalive}`);
  return `${lines.join('\n')}\n`;
}
