import { AmneziaClientConfig } from '../sdk/server_pb';

// The AmneziaWG lines of a client configuration file. A field is written only
// when the server set it, so a server without a profile produces exactly the
// plain WireGuard file it produced before.
//
// S1-S4, H1-H4, the header protection key, random trailers, disabled cookies
// and content padding are the values the server's own interface carries; the
// rest only shapes this client's packets. The header protection key is a secret
// on the server, not from its clients: AmneziaWG encrypts the packet header
// with it, so a client without it cannot read anything.

// AmneziaField is one parameter: the name it is written as, how its value is
// rendered, and where it comes from in the profile.
interface AmneziaField {
  key: string;
  kind: 'number' | 'text' | 'flag';
  read: (amnezia: AmneziaClientConfig.AsObject) => number | string | boolean;
}

// amneziaFields is the one list of parameters, in the order they are written.
// The native builder imports AWG_CONF_KEYS from here rather than repeating the
// names, so a parameter cannot drift between the .conf writer and the reader
// that copies it into AmneziaVPN's JSON.
const amneziaFields: AmneziaField[] = [
  { key: 'Jc', kind: 'number', read: (a) => a.jc },
  { key: 'Jmin', kind: 'number', read: (a) => a.jmin },
  { key: 'Jmax', kind: 'number', read: (a) => a.jmax },
  { key: 'S1', kind: 'number', read: (a) => a.s1 },
  { key: 'S2', kind: 'number', read: (a) => a.s2 },
  { key: 'S3', kind: 'number', read: (a) => a.s3 },
  { key: 'S4', kind: 'number', read: (a) => a.s4 },
  { key: 'H1', kind: 'text', read: (a) => a.h1 },
  { key: 'H2', kind: 'text', read: (a) => a.h2 },
  { key: 'H3', kind: 'text', read: (a) => a.h3 },
  { key: 'H4', kind: 'text', read: (a) => a.h4 },
  { key: 'HeaderProtectionKey', kind: 'text', read: (a) => a.headerProtectionKey },
  { key: 'ContentPaddingAddition', kind: 'text', read: (a) => a.contentPaddingAddition },
  { key: 'RandomTrailers', kind: 'flag', read: (a) => a.randomTrailers },
  { key: 'DisableCookies', kind: 'flag', read: (a) => a.disableCookies },
  { key: 'RekeyAfterTime', kind: 'text', read: (a) => a.rekeyAfterTime },
  { key: 'RekeyTimeout', kind: 'text', read: (a) => a.rekeyTimeout },
  { key: 'RejectAfterTime', kind: 'text', read: (a) => a.rejectAfterTime },
  { key: 'KeepaliveTimeout', kind: 'text', read: (a) => a.keepaliveTimeout },
  { key: 'MaxHandshakeAttempts', kind: 'text', read: (a) => a.maxHandshakeAttempts },
  { key: 'I1', kind: 'text', read: (a) => a.i1 },
  { key: 'I2', kind: 'text', read: (a) => a.i2 },
  { key: 'I3', kind: 'text', read: (a) => a.i3 },
  { key: 'I4', kind: 'text', read: (a) => a.i4 },
  { key: 'I5', kind: 'text', read: (a) => a.i5 },
];

// AWG_CONF_KEYS is every parameter name, for the code that copies the values
// back out of a rendered .conf.
export const AWG_CONF_KEYS = amneziaFields.map((field) => field.key);

export function amneziaLines(amnezia?: AmneziaClientConfig.AsObject): string[] {
  if (!amnezia) {
    return [];
  }

  const lines: string[] = [];
  for (const field of amneziaFields) {
    const value = field.read(amnezia);
    if (field.kind === 'number') {
      if (typeof value === 'number' && value > 0) {
        lines.push(`${field.key} = ${value}`);
      }
    } else if (field.kind === 'text') {
      if (typeof value === 'string' && value) {
        lines.push(`${field.key} = ${value}`);
      }
    } else if (value === true) {
      lines.push(`${field.key} = on`);
    }
  }
  return lines;
}
