import { InfoRes } from '../sdk/server_pb';

// AmneziaWG is WireGuard with obfuscation, and a configuration file carries
// its parameters only when the server has a profile. That is also how the UI
// knows which client the file is for: without a profile the server speaks
// plain WireGuard and the usual client works.
export function isAmnezia(info?: InfoRes.AsObject): boolean {
  return Boolean(info?.amnezia);
}

// clientProductName is the protocol name the instructions use.
export function clientProductName(info?: InfoRes.AsObject): string {
  return isAmnezia(info) ? 'AmneziaWG' : 'WireGuard';
}
