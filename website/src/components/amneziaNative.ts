// AmneziaVPN's native connection format.
//
// A plain WireGuard/AmneziaWG .conf carries no name, and AmneziaVPN names every
// imported config "Server 1", "Server 2", ... itself. Its own format does carry
// one: a JSON document with a "description", wrapped for sharing as
// vpn://base64url(qCompress(json)).
//
// This builds exactly the JSON AmneziaVPN builds internally when it imports our
// .conf (see client/core/controllers/selfhosted/importController.cpp,
// extractWireGuardConfig), with the description filled in from the server.

// Keys the AmneziaWG importer copies from the INI into last_config verbatim.
const AWG_KEYS = [
  'Jc',
  'Jmin',
  'Jmax',
  'S1',
  'S2',
  'S3',
  'S4',
  'H1',
  'H2',
  'H3',
  'H4',
  'I1',
  'I2',
  'I3',
  'I4',
  'I5',
  'HeaderProtectionKey',
  'ContentPaddingAddition',
  'RekeyAfterTime',
  'RekeyTimeout',
  'RejectAfterTime',
  'KeepaliveTimeout',
  'MaxHandshakeAttempts',
  'RandomTrailers',
  'DisableCookies',
];

const DEFAULT_PORT = 51820;

export interface AmneziaNativeConfig {
  /** Pretty JSON, the file the user downloads. */
  json: string;
  /** The endpoint host, used for the file name and the default description. */
  host: string;
}

// parseIni reads the key = value pairs of a WireGuard configuration file,
// ignoring sections and comments the way the client does.
function parseIni(ini: string): Map<string, string> {
  const values = new Map<string, string>();
  for (const raw of ini.split('\n')) {
    const line = raw.trim();
    if (line.length === 0 || line.startsWith('#') || line.startsWith(';')) {
      continue;
    }
    if (line.startsWith('[') && line.endsWith(']')) {
      continue;
    }
    const separator = line.indexOf('=');
    if (separator <= 0) {
      continue;
    }
    values.set(line.slice(0, separator).trim(), line.slice(separator + 1).trim());
  }
  return values;
}

// splitEndpoint separates host and port. IPv6 endpoints are written as
// [addr]:port, so only a colon after the closing bracket counts.
function splitEndpoint(endpoint: string): { host: string; port: number } {
  const value = endpoint.trim();
  if (value.startsWith('[')) {
    const end = value.indexOf(']');
    if (end > 0) {
      const port = value.slice(end + 1).replace(/^:/, '');
      return { host: value.slice(1, end), port: port ? Number(port) : DEFAULT_PORT };
    }
  }
  const colon = value.lastIndexOf(':');
  if (colon > 0 && !value.slice(colon + 1).includes(':')) {
    const port = Number(value.slice(colon + 1));
    if (Number.isFinite(port) && port > 0) {
      return { host: value.slice(0, colon), port };
    }
  }
  return { host: value, port: DEFAULT_PORT };
}

// buildAmneziaNative turns a client .conf into AmneziaVPN's JSON. description
// is what the app will show in its server list.
export function buildAmneziaNative(ini: string, description: string): AmneziaNativeConfig {
  const values = parseIni(ini);

  const privateKey = values.get('PrivateKey');
  const address = values.get('Address');
  const publicKey = values.get('PublicKey');
  if (!privateKey || !address || !publicKey) {
    throw new Error('the configuration is missing PrivateKey, Address or PublicKey');
  }

  const { host, port } = splitEndpoint(values.get('Endpoint') ?? '');

  // last_config is a JSON string inside the container config, not an object.
  const last: Record<string, unknown> = {
    config: ini,
    hostName: host,
    port,
    client_priv_key: privateKey,
    client_ip: address,
    server_pub_key: publicKey,
  };
  const presharedKey = values.get('PresharedKey');
  if (presharedKey) {
    last.psk_key = presharedKey;
  }
  const mtu = values.get('MTU');
  if (mtu) {
    last.mtu = mtu;
  }
  const keepalive = values.get('PersistentKeepalive');
  if (keepalive) {
    last.persistent_keep_alive = keepalive;
  }
  last.allowed_ips = (values.get('AllowedIPs') ?? '')
    .split(',')
    .map((ip) => ip.trim())
    .filter((ip) => ip.length > 0);
  for (const key of AWG_KEYS) {
    const value = values.get(key);
    if (value) {
      last[key] = value;
    }
  }

  const document: Record<string, unknown> = {
    containers: [
      {
        container: 'amnezia-awg',
        awg: {
          last_config: JSON.stringify(last),
          isThirdPartyConfig: true,
          port: String(port),
          transport_proto: 'udp',
        },
      },
    ],
    defaultContainer: 'amnezia-awg',
    description: description || host,
    hostName: host,
  };

  const dns = (values.get('DNS') ?? '')
    .split(/[,\s]+/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  if (dns[0]) {
    document.dns1 = dns[0];
  }
  if (dns[1]) {
    document.dns2 = dns[1];
  }

  return { json: JSON.stringify(document, null, 2), host };
}

function base64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// toVpnUri wraps the JSON the way AmneziaVPN shares it: base64url of
// qCompress(), which is a four-byte big-endian uncompressed length followed by
// a zlib stream. Browsers without CompressionStream get the plain JSON instead
// (the importer accepts that too).
export async function toVpnUri(json: string): Promise<string> {
  if (typeof CompressionStream === 'undefined') {
    return '';
  }
  const rawLength = new TextEncoder().encode(json).length;
  const compressed = await new Response(
    new Blob([json]).stream().pipeThrough(new CompressionStream('deflate')),
  ).arrayBuffer();

  const framed = new Uint8Array(4 + compressed.byteLength);
  new DataView(framed.buffer).setUint32(0, rawLength, false);
  framed.set(new Uint8Array(compressed), 4);

  return 'vpn://' + base64Url(framed);
}
