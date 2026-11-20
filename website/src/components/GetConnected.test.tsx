import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { InfoRes } from '../sdk/server_pb';
import { AppState } from '../AppState';
import { download } from '../Util';
import { GetConnected } from './GetConnected';
import { clientProductName, isAmnezia } from './clientProduct';

vi.mock('../Util', () => ({ download: vi.fn() }));

function serverInfo(overrides: Partial<InfoRes.AsObject> = {}): InfoRes.AsObject {
  return {
    filename: '',
    publicKey: 'serverkey=',
    host: { value: 'vpn.example.com' },
    port: 51820,
    allowedIps: '0.0.0.0/0',
    dnsEnabled: false,
    dnsAddress: '10.44.0.1',
    clientConfigDnsServers: '',
    clientConfigDnsSearchDomain: '',
    clientConfigMtu: 0,
    clientConfigPersistentKeepalive: 0,
    ...overrides,
  } as InfoRes.AsObject;
}

const amnezia = {
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
  i1: '',
  i2: '',
  i3: '',
  i4: '',
  i5: '',
  contentPaddingAddition: '',
  rekeyAfterTime: '',
  rekeyTimeout: '',
  rejectAfterTime: '',
  keepaliveTimeout: '',
  maxHandshakeAttempts: '',
  headerProtectionKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
  randomTrailers: true,
  disableCookies: true,
};

describe('clientProduct', () => {
  it('names the client after the protocol the server speaks', () => {
    expect(isAmnezia(serverInfo())).toBe(false);
    expect(clientProductName(serverInfo())).toBe('WireGuard');

    expect(isAmnezia(serverInfo({ amnezia }))).toBe(true);
    expect(clientProductName(serverInfo({ amnezia }))).toBe('AmneziaWG');
  });
});

describe('GetConnected', () => {
  it('sends a plain WireGuard server to the WireGuard app', () => {
    AppState.setInfo(serverInfo());

    render(<GetConnected configFile="config" showMobile={false} />);

    expect(screen.getByText('1. Install the WireGuard app')).toBeTruthy();
  });

  it('names the AmneziaWG client when the server has a profile', () => {
    AppState.setInfo(serverInfo({ amnezia }));

    render(<GetConnected configFile="config" showMobile={false} />);

    // The WireGuard app cannot import a configuration that carries AmneziaWG
    // parameters, so the instructions must not point at it.
    expect(screen.getByText('1. Install an AmneziaWG client')).toBeTruthy();
    expect(screen.queryByText('1. Install the WireGuard app')).toBeNull();
  });

  it('links to the Amnezia mirror, not the amnezia.org site', () => {
    // amnezia.org is blocked in the networks this fork is meant for; the
    // project publishes a mirror for exactly that case.
    const open = vi.spyOn(window, 'open').mockImplementation(() => null);
    AppState.setInfo(serverInfo({ amnezia }));

    render(<GetConnected configFile="config" showMobile={false} />);
    fireEvent.click(screen.getByText('Download'));

    expect(open).toHaveBeenCalledWith('https://storage.googleapis.com/amnezia/amnezia.org', '__blank', 'noopener noreferrer');
    open.mockRestore();
  });

  it('names a downloaded file after the protocol when the server sets no filename', () => {
    AppState.setInfo(serverInfo({ amnezia }));
    render(<GetConnected configFile="config" showMobile={false} />);

    fireEvent.click(screen.getByText('Connection file'));

    expect(download).toHaveBeenCalledWith({ filename: 'AmneziaWG.conf', content: 'config' });
  });

  it('keeps the WireGuard name for a plain server', () => {
    AppState.setInfo(serverInfo());
    render(<GetConnected configFile="config" showMobile={false} />);

    fireEvent.click(screen.getByText('Connection file'));

    expect(download).toHaveBeenCalledWith({ filename: 'WireGuard.conf', content: 'config' });
  });
});
