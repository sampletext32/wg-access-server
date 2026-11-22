import { ButtonGroup, Box } from '@mui/material';
import Button from '@mui/material/Button';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Paper from '@mui/material/Paper';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';
import Typography from '@mui/material/Typography';
import { GetApp } from '@mui/icons-material';
import ChevronLeft from '@mui/icons-material/ChevronLeft';
import ChevronRight from '@mui/icons-material/ChevronRight';
import Laptop from '@mui/icons-material/Laptop';
import PhoneIphone from '@mui/icons-material/PhoneIphone';
import React, { PropsWithChildren } from 'react';
import { AppState } from '../AppState';
import { isMobile } from '../Platform';
import { download } from '../Util';
import { LinuxIcon } from './Icons';
import AppleIcon from '@mui/icons-material/Apple';
import MicrosoftIcon from '@mui/icons-material/Microsoft';
import { isAmnezia } from './clientProduct';
import { buildAmneziaNative, toQrChunks } from './amneziaNative';
import { QRCode } from './QRCode';
import { TabPanel } from './TabPanel';

interface Props {
  configFile: string;
  showMobile: boolean;
}

export function GetConnected({ configFile, showMobile }: PropsWithChildren<Props>) {
  const [currentTab, setCurrentTab] = React.useState(isMobile() && showMobile ? 'mobile' : 'desktop');
  // An AmneziaWG configuration cannot be imported by the WireGuard app, so the
  // instructions have to name the client that can read it.
  const amnezia = isAmnezia(AppState.info);

  // For AmneziaWG servers the connection is handed over in AmneziaVPN's own
  // format: a JSON document with a description and the endpoint, which is what
  // makes the app show "vpn.example.com" instead of "Server 1". The QR code
  // carries the same document as a vpn:// link.
  const native = React.useMemo(() => {
    if (!amnezia) {
      return undefined;
    }
    try {
      return buildAmneziaNative(configFile, '');
    } catch {
      // A configuration the builder cannot read is still offered as the plain
      // file rather than not at all.
      return undefined;
    }
  }, [amnezia, configFile]);

  // AmneziaVPN scans a series of QR codes, each one a piece of the compressed
  // document; a small document is a single code.
  const [qrCodes, setQrCodes] = React.useState<string[] | undefined>(undefined);
  const [qrIndex, setQrIndex] = React.useState(0);
  React.useEffect(() => {
    let current = true;
    if (!native) {
      setQrCodes([configFile]);
      setQrIndex(0);
      return;
    }
    setQrCodes(undefined);
    setQrIndex(0);
    void toQrChunks(native.json)
      .then((chunks) => {
        if (current) {
          setQrCodes(chunks.length > 0 ? chunks : [native.json]);
        }
      })
      .catch(() => {
        if (current) {
          setQrCodes([native.json]);
        }
      });
    return () => {
      current = false;
    };
  }, [native, configFile]);

  const go = (href: string) => {
    window.open(href, '__blank', 'noopener noreferrer');
  };

  // A multi-code import is driven with the buttons or the arrow keys; the
  // phone shows nothing until the last code has been read.
  React.useEffect(() => {
    if (!qrCodes || qrCodes.length <= 1) {
      return;
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'ArrowRight') {
        event.preventDefault();
        setQrIndex((index) => Math.min(qrCodes.length - 1, index + 1));
      } else if (event.key === 'ArrowLeft') {
        event.preventDefault();
        setQrIndex((index) => Math.max(0, index - 1));
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [qrCodes]);

  const downloadConfigFile = () => {
    const info = AppState.info!;
    if (native) {
      download({ filename: native.host + '.json', content: native.json });
      return;
    }
    download({
      filename: info.filename.length > 0 ? info.filename + '.conf' : amnezia ? 'AmneziaWG.conf' : 'WireGuard.conf',
      content: configFile,
    });
  };

  return (
    <React.Fragment>
      <Paper>
        <Tabs
          value={currentTab}
          onChange={(_, currentTab) => setCurrentTab(currentTab)}
          indicatorColor="primary"
          textColor="primary"
          variant="fullWidth"
        >
          <Tab icon={<Laptop />} value="desktop" />
          {showMobile && <Tab icon={<PhoneIphone />} value="mobile" />}
        </Tabs>
      </Paper>

      <TabPanel for="desktop" value={currentTab}>
        <Box sx={{ display: 'flex', justifyContent: 'space-around', alignItems: 'center' }}>
          <List>
            <ListItem>
              <ListItemText
                style={{ width: 300 }}
                primary={amnezia ? '1. Install AmneziaVPN' : '1. Install the WireGuard app'}
              />
              {amnezia ? (
                <Button variant="outlined" color="primary" onClick={() => go('https://storage.googleapis.com/amnezia/amnezia.org')}>
                  <GetApp /> Download
                </Button>
              ) : (
                <ButtonGroup size="large" color="primary" aria-label="Download the WireGuard app">
                  <Button onClick={() => go('https://www.WireGuard.com/install/')}>
                    <LinuxIcon />
                  </Button>
                  <Button onClick={() => go('https://www.wireguard.com/install/')}>
                    <MicrosoftIcon />
                  </Button>
                  <Button onClick={() => go('https://www.wireguard.com/install/#macos-app-store')}>
                    <AppleIcon />
                  </Button>
                </ButtonGroup>
              )}
            </ListItem>
            <ListItem>
              <ListItemText
                style={{ width: 300 }}
                primary={amnezia ? '2. Download your AmneziaVPN configuration (JSON)' : '2. Download your connection file'}
              />
              <Button variant="outlined" color="primary" onClick={downloadConfigFile}>
                <GetApp /> {amnezia ? 'Configuration' : 'Connection file'}
              </Button>
            </ListItem>
            <ListItem>
              <ListItemText
                style={{ width: 300 }}
                primary={amnezia ? '3. Import the file in AmneziaVPN' : '3. Import your connection file in the app'}
              />
            </ListItem>
          </List>
        </Box>
      </TabPanel>

      {showMobile && (
        <TabPanel for="mobile" value={currentTab}>
          <Box sx={{ display: 'flex', justifyContent: 'space-around', alignItems: 'center' }}>
            <Box>
              <List>
                <ListItem>
                  <ListItemText primary={amnezia ? '1. Install AmneziaVPN' : '1. Install the WireGuard app'} />
                </ListItem>
                <ListItem>
                  <ListItemText primary={amnezia ? '2. Add a connection' : '2. Add a tunnel'} />
                </ListItem>
                <ListItem>
                  <ListItemText primary={amnezia ? '3. Scan the QR code' : '3. Create from QR code'} />
                </ListItem>
              </List>
            </Box>
            <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1 }}>
              {qrCodes && qrCodes.length > 0 && (
                <>
                  <QRCode content={qrCodes[Math.min(qrIndex, qrCodes.length - 1)]} />
                  {qrCodes.length > 1 ? (
                    <>
                      <Typography variant="subtitle2" component="p" sx={{ fontWeight: 600 }}>
                        QR code {Math.min(qrIndex, qrCodes.length - 1) + 1} of {qrCodes.length}
                      </Typography>
                      <Typography
                        variant="caption"
                        component="p"
                        sx={{ maxWidth: 460, textAlign: 'center', color: 'text.secondary' }}
                      >
                        AmneziaVPN shows no progress while scanning. Point the phone at this code, then press Next (or
                        the right arrow key) for the next one. The connection appears only after the last code.
                      </Typography>
                      <ButtonGroup size="small" variant="outlined">
                        <Button
                          startIcon={<ChevronLeft />}
                          disabled={qrIndex <= 0}
                          onClick={() => setQrIndex((index) => Math.max(0, index - 1))}
                        >
                          Previous
                        </Button>
                        <Button
                          endIcon={<ChevronRight />}
                          disabled={qrIndex >= qrCodes.length - 1}
                          onClick={() => setQrIndex((index) => Math.min(qrCodes.length - 1, index + 1))}
                        >
                          Next
                        </Button>
                      </ButtonGroup>
                    </>
                  ) : (
                    <Typography
                      variant="caption"
                      component="p"
                      sx={{ maxWidth: 460, textAlign: 'center', color: 'text.secondary' }}
                    >
                      AmneziaVPN shows no progress while scanning; the connection appears once the app has read this
                      code.
                    </Typography>
                  )}
                </>
              )}
            </Box>
          </Box>
        </TabPanel>
      )}
    </React.Fragment>
  );
}
