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
export function amneziaLines(amnezia?: AmneziaClientConfig.AsObject): string[] {
  if (!amnezia) {
    return [];
  }

  const lines: string[] = [];
  const number = (name: string, value: number) => {
    if (value > 0) {
      lines.push(`${name} = ${value}`);
    }
  };
  const text = (name: string, value: string) => {
    if (value) {
      lines.push(`${name} = ${value}`);
    }
  };
  const flag = (name: string, on: boolean) => {
    if (on) {
      lines.push(`${name} = on`);
    }
  };

  number('Jc', amnezia.jc);
  number('Jmin', amnezia.jmin);
  number('Jmax', amnezia.jmax);

  number('S1', amnezia.s1);
  number('S2', amnezia.s2);
  number('S3', amnezia.s3);
  number('S4', amnezia.s4);

  text('H1', amnezia.h1);
  text('H2', amnezia.h2);
  text('H3', amnezia.h3);
  text('H4', amnezia.h4);

  text('HeaderProtectionKey', amnezia.headerProtectionKey);
  text('ContentPaddingAddition', amnezia.contentPaddingAddition);
  flag('RandomTrailers', amnezia.randomTrailers);
  flag('DisableCookies', amnezia.disableCookies);

  text('RekeyAfterTime', amnezia.rekeyAfterTime);
  text('RekeyTimeout', amnezia.rekeyTimeout);
  text('RejectAfterTime', amnezia.rejectAfterTime);
  text('KeepaliveTimeout', amnezia.keepaliveTimeout);
  text('MaxHandshakeAttempts', amnezia.maxHandshakeAttempts);

  text('I1', amnezia.i1);
  text('I2', amnezia.i2);
  text('I3', amnezia.i3);
  text('I4', amnezia.i4);
  text('I5', amnezia.i5);

  return lines;
}
