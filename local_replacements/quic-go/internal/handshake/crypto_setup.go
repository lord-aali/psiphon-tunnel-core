package handshake

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"

	"github.com/Psiphon-Labs/quic-go/internal/protocol"
	"github.com/Psiphon-Labs/quic-go/internal/qerr"
	"github.com/Psiphon-Labs/quic-go/internal/utils"
	"github.com/Psiphon-Labs/quic-go/internal/wire"
	"github.com/Psiphon-Labs/quic-go/logging"
	"github.com/Psiphon-Labs/quic-go/quicvarint"

	ptls "github.com/Psiphon-Labs/psiphon-tls"
)

type quicVersionContextKey struct{}

var QUICVersionContextKey = &quicVersionContextKey{}

const clientSessionStateRevision = 4

type cryptoSetup struct {
	tlsConf *ptls.Config
	conn    *ptls.QUICConn

	events []Event

	version protocol.Version

	ourParams  *wire.TransportParameters
	peerParams *wire.TransportParameters

	zeroRTTParameters *wire.TransportParameters
	allow0RTT         bool

	// [Psiphon]
	clientHelloPRNG *prng.PRNG

	rttStats *utils.RTTStats

	tracer *logging.ConnectionTracer
	logger utils.Logger

	perspective protocol.Perspective

	handshakeCompleteTime time.Time

	zeroRTTOpener LongHeaderOpener // only set for the server
	zeroRTTSealer LongHeaderSealer // only set for the client

	initialOpener LongHeaderOpener
	initialSealer LongHeaderSealer

	handshakeOpener LongHeaderOpener
	handshakeSealer LongHeaderSealer

	used0RTT atomic.Bool

	aead          *updatableAEAD
	has1RTTSealer bool
	has1RTTOpener bool
}

var _ CryptoSetup = &cryptoSetup{}

// ToPsiphonTLSConfig converts a crypto/tls.Config to a psiphon-tls.Config.
func ToPsiphonTLSConfig(c *tls.Config) *ptls.Config {
	if c == nil {
		return nil
	}
	return (*ptls.Config)(unsafe.Pointer(c.Clone()))
}

// NewCryptoSetupClient creates a new crypto setup for the client
func NewCryptoSetupClient(
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	tlsConf *ptls.Config,

	// [Psiphon]
	clientHelloSeed *prng.Seed,
	getClientHelloRandom func() ([]byte, error),

	enable0RTT bool,
	rttStats *utils.RTTStats,
	tracer *logging.ConnectionTracer,
	logger utils.Logger,
	version protocol.Version,
) CryptoSetup {
	var clientHelloPRNG *prng.PRNG
	if clientHelloSeed != nil {
		clientHelloPRNG = prng.NewPRNGWithSeed(clientHelloSeed)
	}

	cs := newCryptoSetup(
		connID,
		tp,
		rttStats,
		tracer,
		logger,
		protocol.PerspectiveClient,
		version,
	)
	cs.clientHelloPRNG = clientHelloPRNG

	tlsConf = tlsConf.Clone()
	tlsConf.MinVersion = ptls.VersionTLS13
	tlsConf.ClientHelloPRNG = clientHelloPRNG
	tlsConf.GetClientHelloRandom = getClientHelloRandom
	cs.tlsConf = tlsConf
	cs.allow0RTT = enable0RTT

	cs.conn = ptls.QUICClient(&ptls.QUICConfig{
		TLSConfig:           tlsConf,
		EnableSessionEvents: true,
	})
	cs.conn.SetTransportParameters(cs.ourParams.Marshal(protocol.PerspectiveClient, clientHelloPRNG))

	return cs
}

// NewCryptoSetupServer creates a new crypto setup for the server
func NewCryptoSetupServer(
	connID protocol.ConnectionID,
	localAddr, remoteAddr net.Addr,
	tp *wire.TransportParameters,
	tlsConf *ptls.Config,
	allow0RTT bool,
	rttStats *utils.RTTStats,
	tracer *logging.ConnectionTracer,
	logger utils.Logger,
	version protocol.Version,
) CryptoSetup {
	cs := newCryptoSetup(
		connID,
		tp,
		rttStats,
		tracer,
		logger,
		protocol.PerspectiveServer,
		version,
	)
	cs.allow0RTT = allow0RTT

	tlsConf = setupConfigForServer(tlsConf, localAddr, remoteAddr)
	cs.tlsConf = tlsConf
	cs.conn = ptls.QUICServer(&ptls.QUICConfig{
		TLSConfig:           tlsConf,
		EnableSessionEvents: true,
	})
	return cs
}

func newCryptoSetup(
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	rttStats *utils.RTTStats,
	tracer *logging.ConnectionTracer,
	logger utils.Logger,
	perspective protocol.Perspective,
	version protocol.Version,
) *cryptoSetup {
	initialSealer, initialOpener := NewInitialAEAD(connID, perspective, version)
	if tracer != nil && tracer.UpdatedKeyFromTLS != nil {
		tracer.UpdatedKeyFromTLS(protocol.EncryptionInitial, protocol.PerspectiveClient)
		tracer.UpdatedKeyFromTLS(protocol.EncryptionInitial, protocol.PerspectiveServer)
	}
	return &cryptoSetup{
		initialSealer: initialSealer,
		initialOpener: initialOpener,
		aead:          newUpdatableAEAD(rttStats, tracer, logger, version),
		events:        make([]Event, 0, 16),
		ourParams:     tp,
		rttStats:      rttStats,
		tracer:        tracer,
		logger:        logger,
		perspective:   perspective,
		version:       version,
	}
}

func (h *cryptoSetup) ChangeConnectionID(id protocol.ConnectionID) {
	initialSealer, initialOpener := NewInitialAEAD(id, h.perspective, h.version)
	h.initialSealer = initialSealer
	h.initialOpener = initialOpener
	if h.tracer != nil && h.tracer.UpdatedKeyFromTLS != nil {
		h.tracer.UpdatedKeyFromTLS(protocol.EncryptionInitial, protocol.PerspectiveClient)
		h.tracer.UpdatedKeyFromTLS(protocol.EncryptionInitial, protocol.PerspectiveServer)
	}
}

func (h *cryptoSetup) SetLargest1RTTAcked(pn protocol.PacketNumber) error {
	return h.aead.SetLargestAcked(pn)
}

func (h *cryptoSetup) StartHandshake(ctx context.Context) error {
	err := h.conn.Start(context.WithValue(ctx, QUICVersionContextKey, h.version))
	if err != nil {
		return wrapError(err)
	}
	for {
		ev := h.conn.NextEvent()
		if err := h.handleEvent(ev); err != nil {
			return wrapError(err)
		}
		if ev.Kind == ptls.QUICNoEvent {
			break
		}
	}
	if h.perspective == protocol.PerspectiveClient {
		if h.zeroRTTSealer != nil && h.zeroRTTParameters != nil {
			h.logger.Debugf("Doing 0-RTT.")
			h.events = append(h.events, Event{Kind: EventRestoredTransportParameters, TransportParameters: h.zeroRTTParameters})
		} else {
			h.logger.Debugf("Not doing 0-RTT. Has sealer: %t, has params: %t", h.zeroRTTSealer != nil, h.zeroRTTParameters != nil)
		}
	}
	return nil
}

// Close closes the crypto setup.
// It aborts the handshake, if it is still running.
func (h *cryptoSetup) Close() error {
	return h.conn.Close()
}

// HandleMessage handles a TLS handshake message.
// It is called by the crypto streams when a new message is available.
func (h *cryptoSetup) HandleMessage(data []byte, encLevel protocol.EncryptionLevel) error {
	if err := h.handleMessage(data, encLevel); err != nil {
		return wrapError(err)
	}
	return nil
}

func (h *cryptoSetup) handleMessage(data []byte, encLevel protocol.EncryptionLevel) error {
	if err := h.conn.HandleData(encLevel.ToTLSEncryptionLevel(), data); err != nil {
		return err
	}
	for {
		ev := h.conn.NextEvent()
		if err := h.handleEvent(ev); err != nil {
			return err
		}
		if ev.Kind == ptls.QUICNoEvent {
			return nil
		}
	}
}

func (h *cryptoSetup) handleEvent(ev ptls.QUICEvent) (err error) {
	switch ev.Kind {
	case ptls.QUICNoEvent:
		return nil
	case ptls.QUICSetReadSecret:
		h.setReadKey(ev.Level, ev.Suite, ev.Data)
		return nil
	case ptls.QUICSetWriteSecret:
		h.setWriteKey(ev.Level, ev.Suite, ev.Data)
		return nil
	case ptls.QUICTransportParameters:
		return h.handleTransportParameters(ev.Data)
	case ptls.QUICTransportParametersRequired:
		h.conn.SetTransportParameters(h.ourParams.Marshal(h.perspective, h.clientHelloPRNG))
		return nil
	case ptls.QUICRejectedEarlyData:
		h.rejected0RTT()
		return nil
	case ptls.QUICWriteData:
		h.writeRecord(ev.Level, ev.Data)
		return nil
	case ptls.QUICHandshakeDone:
		h.handshakeComplete()
		return nil
	case ptls.QUICStoreSession:
		if h.perspective == protocol.PerspectiveServer {
			panic("cryptoSetup BUG: unexpected QUICStoreSession event for the server")
		}
		ev.SessionState.Extra = append(
			ev.SessionState.Extra,
			addSessionStateExtraPrefix(h.marshalDataForSessionState(ev.SessionState.EarlyData)),
		)
		return h.conn.StoreSession(ev.SessionState)
	case ptls.QUICResumeSession:
		var allowEarlyData bool
		switch h.perspective {
		case protocol.PerspectiveClient:
			allowEarlyData = h.handleDataFromSessionState(
				findSessionStateExtraData(ev.SessionState.Extra),
				ev.SessionState.EarlyData,
			)
		case protocol.PerspectiveServer:
			allowEarlyData = h.handleSessionTicket(
				findSessionStateExtraData(ev.SessionState.Extra),
				ev.SessionState.EarlyData,
			)
		}
		if ev.SessionState.EarlyData {
			ev.SessionState.EarlyData = allowEarlyData
		}
		return nil
	default:
		return nil
	}
}

func (h *cryptoSetup) NextEvent() Event {
	if len(h.events) == 0 {
		return Event{Kind: EventNoEvent}
	}
	ev := h.events[0]
	h.events = h.events[1:]
	return ev
}

func (h *cryptoSetup) handleTransportParameters(data []byte) error {
	var tp wire.TransportParameters
	if err := tp.Unmarshal(data, h.perspective.Opposite()); err != nil {
		return err
	}
	h.peerParams = &tp
	h.events = append(h.events, Event{Kind: EventReceivedTransportParameters, TransportParameters: h.peerParams})
	return nil
}

// must be called after receiving the transport parameters
func (h *cryptoSetup) marshalDataForSessionState(earlyData bool) []byte {
	b := make([]byte, 0, 256)
	b = quicvarint.Append(b, clientSessionStateRevision)
	b = quicvarint.Append(b, uint64(h.rttStats.SmoothedRTT().Microseconds()))
	if earlyData {
		return h.peerParams.MarshalForSessionTicket(b)
	}
	return b
}

func (h *cryptoSetup) handleDataFromSessionState(data []byte, earlyData bool) (allowEarlyData bool) {
	rtt, tp, err := decodeDataFromSessionState(data, earlyData)
	if err != nil {
		h.logger.Debugf("Restoring of transport parameters from session ticket failed: %s", err.Error())
		return
	}
	h.rttStats.SetInitialRTT(rtt)
	if tp != nil && h.allow0RTT {
		h.zeroRTTParameters = tp
		return true
	}
	return false
}

func decodeDataFromSessionState(b []byte, earlyData bool) (time.Duration, *wire.TransportParameters, error) {
	ver, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, nil, err
	}
	b = b[l:]
	if ver != clientSessionStateRevision {
		return 0, nil, fmt.Errorf("mismatching version. Got %d, expected %d", ver, clientSessionStateRevision)
	}
	rttEncoded, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, nil, err
	}
	b = b[l:]
	rtt := time.Duration(rttEncoded) * time.Microsecond
	if !earlyData {
		return rtt, nil, nil
	}
	var tp wire.TransportParameters
	if err := tp.UnmarshalFromSessionTicket(b); err != nil {
		return 0, nil, err
	}
	return rtt, &tp, nil
}

func (h *cryptoSetup) getDataForSessionTicket() []byte {
	ticket := &sessionTicket{
		RTT: h.rttStats.SmoothedRTT(),
	}
	if h.allow0RTT {
		ticket.Parameters = h.ourParams
	}
	return ticket.Marshal()
}

// GetSessionTicket generates a new session ticket.
// Due to limitations in crypto/tls, it's only possible to generate a single session ticket per connection.
// It is only valid for the server.
func (h *cryptoSetup) GetSessionTicket() ([]byte, error) {
	if err := h.conn.SendSessionTicket(ptls.QUICSessionTicketOptions{
		EarlyData: h.allow0RTT,
		Extra:     [][]byte{addSessionStateExtraPrefix(h.getDataForSessionTicket())},
	}); err != nil {
		if strings.Contains(err.Error(), "session ticket keys unavailable") {
			return nil, nil
		}
		return nil, err
	}
	ev := h.conn.NextEvent()
	if ev.Kind != ptls.QUICWriteData || ev.Level != ptls.QUICEncryptionLevelApplication {
		panic("crypto/tls bug: where's my session ticket?")
	}
	ticket := ev.Data
	if ev := h.conn.NextEvent(); ev.Kind != ptls.QUICNoEvent {
		panic("crypto/tls bug: why more than one ticket?")
	}
	return ticket, nil
}

func (h *cryptoSetup) handleSessionTicket(data []byte, using0RTT bool) (allowEarlyData bool) {
	var t sessionTicket
	if err := t.Unmarshal(data, using0RTT); err != nil {
		h.logger.Debugf("Unmarshalling session ticket failed: %s", err.Error())
		return false
	}
	h.rttStats.SetInitialRTT(t.RTT)
	if !using0RTT {
		return false
	}
	valid := h.ourParams.ValidFor0RTT(t.Parameters)
	if !valid {
		h.logger.Debugf("Transport parameters changed. Rejecting 0-RTT.")
		return false
	}
	if !h.allow0RTT {
		h.logger.Debugf("0-RTT not allowed. Rejecting 0-RTT.")
		return false
	}
	h.logger.Debugf("Accepting 0-RTT. Restoring RTT from session ticket: %s", t.RTT)
	return true
}

func (h *cryptoSetup) rejected0RTT() {
	h.logger.Debugf("0-RTT was rejected. Dropping 0-RTT keys.")

	had0RTTKeys := h.zeroRTTSealer != nil
	h.zeroRTTSealer = nil

	if had0RTTKeys {
		h.events = append(h.events, Event{Kind: EventDiscard0RTTKeys})
	}
}

func (h *cryptoSetup) setReadKey(el ptls.QUICEncryptionLevel, suiteID uint16, trafficSecret []byte) {
	suite := getCipherSuite(suiteID)
	switch el {
	case ptls.QUICEncryptionLevelEarly:
		if h.perspective == protocol.PerspectiveClient {
			panic("Received 0-RTT read key for the client")
		}
		h.zeroRTTOpener = newLongHeaderOpener(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		h.used0RTT.Store(true)
		if h.logger.Debug() {
			h.logger.Debugf("Installed 0-RTT Read keys (using %s)", ptls.CipherSuiteName(suite.ID))
		}
	case ptls.QUICEncryptionLevelHandshake:
		h.handshakeOpener = newLongHeaderOpener(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		if h.logger.Debug() {
			h.logger.Debugf("Installed Handshake Read keys (using %s)", ptls.CipherSuiteName(suite.ID))
		}
	case ptls.QUICEncryptionLevelApplication:
		h.aead.SetReadKey(suite, trafficSecret)
		h.has1RTTOpener = true
		if h.logger.Debug() {
			h.logger.Debugf("Installed 1-RTT Read keys (using %s)", ptls.CipherSuiteName(suite.ID))
		}
	default:
		panic("unexpected read encryption level")
	}
	h.events = append(h.events, Event{Kind: EventReceivedReadKeys})
	if h.tracer != nil && h.tracer.UpdatedKeyFromTLS != nil {
		h.tracer.UpdatedKeyFromTLS(protocol.FromTLSEncryptionLevel(el), h.perspective.Opposite())
	}
}

func (h *cryptoSetup) setWriteKey(el ptls.QUICEncryptionLevel, suiteID uint16, trafficSecret []byte) {
	suite := getCipherSuite(suiteID)
	switch el {
	case ptls.QUICEncryptionLevelEarly:
		if h.perspective == protocol.PerspectiveServer {
			panic("Received 0-RTT write key for the server")
		}
		h.zeroRTTSealer = newLongHeaderSealer(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		if h.logger.Debug() {
			h.logger.Debugf("Installed 0-RTT Write keys (using %s)", ptls.CipherSuiteName(suite.ID))
		}
		if h.tracer != nil && h.tracer.UpdatedKeyFromTLS != nil {
			h.tracer.UpdatedKeyFromTLS(protocol.Encryption0RTT, h.perspective)
		}
		return
	case ptls.QUICEncryptionLevelHandshake:
		h.handshakeSealer = newLongHeaderSealer(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		if h.logger.Debug() {
			h.logger.Debugf("Installed Handshake Write keys (using %s)", ptls.CipherSuiteName(suite.ID))
		}
	case ptls.QUICEncryptionLevelApplication:
		h.aead.SetWriteKey(suite, trafficSecret)
		h.has1RTTSealer = true
		if h.logger.Debug() {
			h.logger.Debugf("Installed 1-RTT Write keys (using %s)", ptls.CipherSuiteName(suite.ID))
		}
		if h.zeroRTTSealer != nil {
			h.used0RTT.Store(true)
			h.zeroRTTSealer = nil
			h.logger.Debugf("Dropping 0-RTT keys.")
			if h.tracer != nil && h.tracer.DroppedEncryptionLevel != nil {
				h.tracer.DroppedEncryptionLevel(protocol.Encryption0RTT)
			}
		}
	default:
		panic("unexpected write encryption level")
	}
	if h.tracer != nil && h.tracer.UpdatedKeyFromTLS != nil {
		h.tracer.UpdatedKeyFromTLS(protocol.FromTLSEncryptionLevel(el), h.perspective)
	}
}

func (h *cryptoSetup) writeRecord(encLevel ptls.QUICEncryptionLevel, p []byte) {
	switch encLevel {
	case ptls.QUICEncryptionLevelInitial:
		h.events = append(h.events, Event{Kind: EventWriteInitialData, Data: p})
	case ptls.QUICEncryptionLevelHandshake:
		h.events = append(h.events, Event{Kind: EventWriteHandshakeData, Data: p})
	case ptls.QUICEncryptionLevelApplication:
		panic("unexpected write")
	default:
		panic(fmt.Sprintf("unexpected write encryption level: %s", encLevel))
	}
}

func (h *cryptoSetup) DiscardInitialKeys() {
	dropped := h.initialOpener != nil
	h.initialOpener = nil
	h.initialSealer = nil
	if dropped {
		h.logger.Debugf("Dropping Initial keys.")
	}
}

func (h *cryptoSetup) handshakeComplete() {
	h.handshakeCompleteTime = time.Now()
	h.events = append(h.events, Event{Kind: EventHandshakeComplete})
}

func (h *cryptoSetup) SetHandshakeConfirmed() {
	h.aead.SetHandshakeConfirmed()
	var dropped bool
	if h.handshakeOpener != nil {
		h.handshakeOpener = nil
		h.handshakeSealer = nil
		dropped = true
	}
	if dropped {
		h.logger.Debugf("Dropping Handshake keys.")
	}
}

func (h *cryptoSetup) GetInitialSealer() (LongHeaderSealer, error) {
	if h.initialSealer == nil {
		return nil, ErrKeysDropped
	}
	return h.initialSealer, nil
}

func (h *cryptoSetup) Get0RTTSealer() (LongHeaderSealer, error) {
	if h.zeroRTTSealer == nil {
		return nil, ErrKeysDropped
	}
	return h.zeroRTTSealer, nil
}

func (h *cryptoSetup) GetHandshakeSealer() (LongHeaderSealer, error) {
	if h.handshakeSealer == nil {
		if h.initialSealer == nil {
			return nil, ErrKeysDropped
		}
		return nil, ErrKeysNotYetAvailable
	}
	return h.handshakeSealer, nil
}

func (h *cryptoSetup) Get1RTTSealer() (ShortHeaderSealer, error) {
	if !h.has1RTTSealer {
		return nil, ErrKeysNotYetAvailable
	}
	return h.aead, nil
}

func (h *cryptoSetup) GetInitialOpener() (LongHeaderOpener, error) {
	if h.initialOpener == nil {
		return nil, ErrKeysDropped
	}
	return h.initialOpener, nil
}

func (h *cryptoSetup) Get0RTTOpener() (LongHeaderOpener, error) {
	if h.zeroRTTOpener == nil {
		if h.initialOpener != nil {
			return nil, ErrKeysNotYetAvailable
		}
		return nil, ErrKeysDropped
	}
	return h.zeroRTTOpener, nil
}

func (h *cryptoSetup) GetHandshakeOpener() (LongHeaderOpener, error) {
	if h.handshakeOpener == nil {
		if h.initialOpener != nil {
			return nil, ErrKeysNotYetAvailable
		}
		return nil, ErrKeysDropped
	}
	return h.handshakeOpener, nil
}

func (h *cryptoSetup) Get1RTTOpener() (ShortHeaderOpener, error) {
	if h.zeroRTTOpener != nil && time.Since(h.handshakeCompleteTime) > 3*h.rttStats.PTO(true) {
		h.zeroRTTOpener = nil
		h.logger.Debugf("Dropping 0-RTT keys.")
		if h.tracer != nil && h.tracer.DroppedEncryptionLevel != nil {
			h.tracer.DroppedEncryptionLevel(protocol.Encryption0RTT)
		}
	}

	if !h.has1RTTOpener {
		return nil, ErrKeysNotYetAvailable
	}
	return h.aead, nil
}

func (h *cryptoSetup) ConnectionState() ConnectionState {
	cs := h.conn.ConnectionState()
	return ConnectionState{
		ConnectionState: *ptls.UnsafeFromConnectionState(&cs),
		Used0RTT:        h.used0RTT.Load(),
	}
}

// [Psiphon]
func (h *cryptoSetup) TLSConnectionMetrics() {
	h.conn.TLSConnectionMetrics()
}

func wrapError(err error) error {
	if alertErr := ptls.AlertError(0); errors.As(err, &alertErr) {
		return qerr.NewLocalCryptoError(uint8(alertErr), err)
	}
	return &qerr.TransportError{ErrorCode: qerr.InternalError, ErrorMessage: err.Error()}
}
