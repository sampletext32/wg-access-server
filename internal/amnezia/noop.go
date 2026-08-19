package amnezia

type NoOp struct{}

func NewNoOp() Interface                            { return NoOp{} }
func (NoOp) Configure(DeviceConfig) error           { return nil }
func (NoOp) AddPeer(string, string, []string) error { return nil }
func (NoOp) ListPeers() ([]Peer, error)             { return nil, nil }
func (NoOp) RemovePeer(string) error                { return nil }
func (NoOp) PublicKey() (string, error)             { return "", nil }
func (NoOp) Ping() error                            { return nil }
func (NoOp) Close() error                           { return nil }
