import { describe, expect, it, vi } from 'vitest';
import { clientConfig } from './AddDevice';
import { AmneziaClientConfig, InfoRes } from '../sdk/server_pb';

vi.mock('../Api', () => ({ grpc: {} }));

function serverInfo(overrides: Partial<InfoRes.AsObject> = {}): InfoRes.AsObject {
  return {
    publicKey: 'serverkey=',
    host: { value: 'vpn.example.com' },
    port: 51820,
    allowedIps: '0.0.0.0/0, ::/0',
    dnsEnabled: false,
    dnsAddress: '10.44.0.1, fd48:4c4:7aa9::1',
    clientConfigDnsServers: '',
    clientConfigDnsSearchDomain: '',
    clientConfigMtu: 0,
    clientConfigPersistentKeepalive: 0,
    ...overrides,
  } as InfoRes.AsObject;
}

function config(overrides: Partial<InfoRes.AsObject> = {}, opts: Partial<Parameters<typeof clientConfig>[0]> = {}) {
  return clientConfig({
    info: serverInfo(overrides),
    privateKey: 'devicekey=',
    address: '10.44.0.2/32',
    presharedKey: '',
    persistentKeepalive: 0,
    ...opts,
  });
}

describe('clientConfig', () => {
  it('writes what a client needs to connect', () => {
    const file = config();
    expect(file).toContain('PrivateKey = devicekey=');
    expect(file).toContain('Address = 10.44.0.2/32');
    expect(file).toContain('PublicKey = serverkey=');
    expect(file).toContain('AllowedIPs = 0.0.0.0/0, ::/0');
    expect(file).toContain('Endpoint = vpn.example.com:51820');
  });

  it('leaves out what is not configured', () => {
    const file = config();
    expect(file).not.toContain('DNS =');
    expect(file).not.toContain('MTU =');
    expect(file).not.toContain('PresharedKey =');
    expect(file).not.toContain('PersistentKeepalive =');
  });

  it('hands out the servers own DNS when it proxies DNS', () => {
    expect(config({ dnsEnabled: true })).toContain('DNS = 10.44.0.1, fd48:4c4:7aa9::1');
  });

  it('prefers the DNS servers the operator configured for clients', () => {
    const file = config({ dnsEnabled: true, clientConfigDnsServers: '9.9.9.9' });
    expect(file).toContain('DNS = 9.9.9.9');
    expect(file).not.toContain('10.44.0.1');
  });

  it('appends the search domain to the DNS line', () => {
    expect(config({ dnsEnabled: true, clientConfigDnsSearchDomain: 'vpn.home.arpa' })).toContain(
      'DNS = 10.44.0.1, fd48:4c4:7aa9::1, vpn.home.arpa',
    );
  });

  it('writes the MTU and the keepalive when they are set', () => {
    expect(config({ clientConfigMtu: 1280 })).toContain('MTU = 1280');
    expect(config({}, { persistentKeepalive: 25 })).toContain('PersistentKeepalive = 25');
  });

  it('writes the pre-shared key only when the device has one', () => {
    expect(config({}, { presharedKey: 'shared=' })).toContain('PresharedKey = shared=');
  });

  it('falls back to the address the browser is on when the server has no external host', () => {
    expect(config({ host: undefined, port: 0 })).toContain(`Endpoint = ${window.location.hostname}:51820`);
  });

  it('writes the AmneziaWG profile the server hands out', () => {
    const file = config({ amnezia: amneziaProfile() });

    // shared with the server, so its interface and the client agree
    expect(file).toContain('S1 = 17');
    expect(file).toContain('S2 = 29');
    expect(file).toContain('S3 = 43');
    expect(file).toContain('S4 = 12');
    expect(file).toContain('H1 = 123456-123500');
    expect(file).toContain('H4 = 32345-32350');
    // client-only
    expect(file).toContain('Jc = 4');
    expect(file).toContain('Jmin = 500');
    expect(file).toContain('Jmax = 1000');
    expect(file).toContain('I1 = <b 0xf6ab3267fa><c><t>');
    expect(file).toContain('ContentPaddingAddition = 10-20');
  });

  it('writes the AmneziaWG lines into the interface section', () => {
    const file = config({ amnezia: amneziaProfile() });
    const s1 = file.indexOf('S1 = 17');
    expect(s1).toBeGreaterThan(0);
    expect(s1).toBeLessThan(file.indexOf('[Peer]'));
  });

  it('leaves the AmneziaWG lines out when the server has no profile', () => {
    const file = config();
    for (const line of ['Jc =', 'S1 =', 'H1 =', 'I1 =', 'ContentPaddingAddition =']) {
      expect(file).not.toContain(line);
    }
  });
});

// amneziaProfile is the client half of a profile as the server sends it.
function amneziaProfile(): AmneziaClientConfig.AsObject {
  return {
    jc: 4,
    jmin: 500,
    jmax: 1000,
    s1: 17,
    s2: 29,
    s3: 43,
    s4: 12,
    h1: '123456-123500',
    h2: '67543-67550',
    h3: '123123-123200',
    h4: '32345-32350',
    i1: '<b 0xf6ab3267fa><c><t>',
    i2: '',
    i3: '',
    i4: '',
    i5: '',
    contentPaddingAddition: '10-20',
    rekeyAfterTime: '',
    rekeyTimeout: '',
    rejectAfterTime: '',
    keepaliveTimeout: '',
    maxHandshakeAttempts: '',
  };
}
