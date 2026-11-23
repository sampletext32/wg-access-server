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

import { AWG_CONF_KEYS } from './amnezia';

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
  for (const key of AWG_CONF_KEYS) {
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

// qrChunkSize is how many compressed bytes go into one QR code. AmneziaVPN
// accepts up to 850 (its own exporter uses that), but at 850 the code has too
// many modules for a phone camera pointed at a laptop screen; smaller pieces
// give shorter, much easier to scan codes at the cost of one or two more of
// them.
const QR_CHUNK_SIZE = 400;

// qrMagicCode marks a QR code as one chunk of a multi-code config
// (qrCodeUtils.h: qrMagicCode = 1984).
const QR_MAGIC = 1984;

// toQrChunks turns the JSON into the QR payloads AmneziaVPN scans: the JSON is
// compressed the way qCompress does it (four-byte big-endian length + zlib),
// split into 850-byte pieces, and each piece is prefixed with the magic code,
// the number of pieces and its own index before base64url encoding. A document
// that compresses small enough is a single code.
//
// Browsers without CompressionStream get no chunks; the caller falls back to
// the raw JSON, which the importer also accepts.
export async function toQrChunks(json: string): Promise<string[]> {
  if (typeof CompressionStream === 'undefined') {
    return [];
  }
  const rawLength = new TextEncoder().encode(json).length;
  const compressed = await new Response(
    new Blob([json]).stream().pipeThrough(new CompressionStream('deflate')),
  ).arrayBuffer();

  // qCompress framing: uncompressed length, big-endian, then a zlib stream.
  const framed = new Uint8Array(4 + compressed.byteLength);
  new DataView(framed.buffer).setUint32(0, rawLength, false);
  framed.set(new Uint8Array(compressed), 4);

  const count = Math.ceil(framed.length / QR_CHUNK_SIZE);
  const chunks: string[] = [];
  for (let index = 0; index < count; index++) {
    const part = framed.subarray(index * QR_CHUNK_SIZE, Math.min((index + 1) * QR_CHUNK_SIZE, framed.length));
    // QDataStream writes a QByteArray with a four-byte big-endian length in
    // front of the bytes, so the chunk is: magic, count, index, length, data.
    const payload = new Uint8Array(8 + part.length);
    const header = new DataView(payload.buffer);
    header.setUint16(0, QR_MAGIC, false);
    payload[2] = count;
    payload[3] = index;
    header.setUint32(4, part.length, false);
    payload.set(part, 8);
    chunks.push(base64Url(payload));
  }
  return chunks;
}
