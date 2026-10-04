// Package ssmsession is a native Go client for the AWS Systems Manager Session Manager data channel.
//
// It speaks the same websocket protocol as the session-manager-plugin binary, but only implements
// what an SSH ProxyCommand needs: a "Port" session whose byte stream is bridged to an io.Reader and
// io.Writer (normally stdin and stdout).
package ssmsession

import (
	"container/list"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/wrouesnel/ssm-proxycommand/pkg/ssmproto"
)

// ClientVersion is reported to the agent. The agent gates protocol features on the client
// version, so this tracks the session-manager-plugin release whose behaviour we implement.
const ClientVersion = "1.2.707.0"

const (
	// maxPayloadSize matches the chunk size session-manager-plugin uses for stream data.
	maxPayloadSize = 1024
	// sendWindow caps unacknowledged outgoing messages, well under the agent's 10000 entry buffer.
	sendWindow = 2048
	// incomingBufferCap caps out-of-order messages held while waiting for a gap to fill.
	incomingBufferCap = 10000

	defaultRTT         = 100 * time.Millisecond
	defaultRTO         = 200 * time.Millisecond
	maxRTO             = 1 * time.Second
	clockGranularity   = 10 * time.Millisecond
	resendInterval     = 100 * time.Millisecond
	resendTimeout      = 5 * time.Minute
	writeTimeout       = 30 * time.Second
	pingInterval       = 30 * time.Second
	pongTimeout        = 3 * pingInterval
	reconnectTimeout   = 2 * time.Minute
	drainTimeout       = 10 * time.Second
	terminateAckWait   = 2 * time.Second
	defaultHandshakeTO = 30 * time.Second

	// Agents older than this do not understand the TerminateSession flag.
	terminateFlagMinAgentVersion = "2.3.722.0"

	signingService = "ssmmessages"
	// SHA-256 of the empty string, the payload hash for signing the websocket upgrade.
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// ResumeFunc obtains a fresh token, and optionally a new stream URL, for an existing session
// after the websocket drops. It is normally a wrapper around ssm:ResumeSession. An empty token
// with a nil error means the session can no longer be resumed.
type ResumeFunc func(ctx context.Context) (token, streamURL string, err error)

// Options configures a data channel session. SessionID, StreamURL, TokenValue and TargetID come
// from ssm:StartSession.
type Options struct {
	SessionID  string
	StreamURL  string
	TokenValue string
	TargetID   string

	// Region and Credentials are used to SigV4 sign the websocket upgrade when the stream URL
	// is not presigned. Both are optional.
	Region      string
	Credentials aws.CredentialsProvider

	// KMS is required when Session Manager preferences enforce KMS encryption.
	KMS KMSClient

	// Resume enables transparent reconnection when the websocket drops.
	Resume ResumeFunc

	// Logger receives diagnostics. Nil discards them.
	Logger *slog.Logger
	// Stderr receives agent-provided messages meant for the user. Nil discards them.
	Stderr io.Writer
	// Dialer overrides the websocket dialer.
	Dialer *websocket.Dialer
	// HandshakeTimeout bounds the wait for the agent's session handshake.
	HandshakeTimeout time.Duration
}

// errShutdown is the cancellation cause for a session that ended normally.
var errShutdown = errors.New("session ended")

// ErrSessionExpired is returned when a dropped session can no longer be resumed.
var ErrSessionExpired = errors.New("session expired or was terminated and cannot be resumed")

type outMsg struct {
	seq       int64
	raw       []byte
	firstSent time.Time
	lastSent  time.Time
	resent    bool
}

type session struct {
	opts     Options
	log      *slog.Logger
	stderr   io.Writer
	dialer   *websocket.Dialer
	clientID string

	ctx    context.Context
	cancel context.CancelCauseFunc

	// connMu guards conn and streamURL. Writes are serialised by wmu.
	connMu    sync.Mutex
	conn      *websocket.Conn
	streamURL string
	wmu       sync.Mutex

	// mu guards the outgoing stream state.
	mu       sync.Mutex
	cond     *sync.Cond
	nextSeq  int64
	unacked  *list.List
	paused   bool
	rtt      float64
	rttVar   float64
	rto      time.Duration
	enc      *ssmproto.Encrypter
	agentVer string

	// Incoming stream state, owned by the reader goroutine.
	expectedSeq int64
	pending     map[int64]*ssmproto.Message

	handshakeDone chan struct{}
	handshakeOnce sync.Once
	outCh         chan []byte
	outputDone    chan struct{}
}

// Run opens the data channel and bridges it to in and out until the input reaches EOF, the remote
// side closes the channel, ctx is cancelled, or an unrecoverable error occurs. A normal end of
// session returns nil.
func Run(ctx context.Context, opts Options, in io.Reader, out io.Writer) error {
	s := newSession(opts)
	return s.run(ctx, in, out)
}

func newSession(opts Options) *session {
	s := &session{
		opts:          opts,
		log:           opts.Logger,
		stderr:        opts.Stderr,
		dialer:        opts.Dialer,
		clientID:      uuid.NewString(),
		streamURL:     opts.StreamURL,
		unacked:       list.New(),
		rtt:           float64(defaultRTT),
		rto:           defaultRTO,
		pending:       make(map[int64]*ssmproto.Message),
		handshakeDone: make(chan struct{}),
		outCh:         make(chan []byte, 256),
		outputDone:    make(chan struct{}),
	}
	s.cond = sync.NewCond(&s.mu)
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.stderr == nil {
		s.stderr = io.Discard
	}
	if s.dialer == nil {
		d := *websocket.DefaultDialer
		d.Proxy = http.ProxyFromEnvironment
		s.dialer = &d
	}
	if s.opts.HandshakeTimeout == 0 {
		s.opts.HandshakeTimeout = defaultHandshakeTO
	}
	return s
}

func (s *session) run(parent context.Context, in io.Reader, out io.Writer) error {
	s.ctx, s.cancel = context.WithCancelCause(parent)
	defer s.cancel(errShutdown)
	// Wake any sender blocked on flow control once the session ends.
	stop := context.AfterFunc(s.ctx, func() {
		s.mu.Lock()
		s.cond.Broadcast()
		s.mu.Unlock()
	})
	defer stop()

	conn, err := s.dialWithRetry(s.opts.StreamURL, s.opts.TokenValue)
	if err != nil {
		return err
	}
	s.setConn(conn)
	defer s.closeConn()

	go s.writeOutput(out)
	go s.readLoop()
	go s.retransmitLoop()
	go s.pingLoop()

	hsTimer := time.NewTimer(s.opts.HandshakeTimeout)
	defer hsTimer.Stop()
	select {
	case <-s.handshakeDone:
	case <-hsTimer.C:
		s.fail(errors.New("timed out waiting for the session handshake from the SSM agent"))
	case <-s.outputDone:
		s.fail(errors.New("the SSM agent closed the session before the handshake completed"))
	case <-s.ctx.Done():
	}
	if s.ctx.Err() != nil {
		return s.result()
	}

	inputDone := make(chan error, 1)
	go func() { inputDone <- s.pumpInput(in) }()

	select {
	case err := <-inputDone:
		if err != nil {
			s.fail(fmt.Errorf("reading input: %w", err))
			break
		}
		s.log.Debug("input closed, ending session")
		s.finishInput()
		s.shutdown()
	case <-s.outputDone:
		s.log.Debug("remote closed the session")
		s.shutdown()
	case <-s.ctx.Done():
	}
	return s.result()
}

func (s *session) result() error {
	err := context.Cause(s.ctx)
	if errors.Is(err, errShutdown) {
		return nil
	}
	return err
}

func (s *session) fail(err error) {
	s.log.Debug("session failed", "error", err)
	s.cancel(err)
	s.closeConn()
}

func (s *session) shutdown() {
	s.connMu.Lock()
	c := s.conn
	s.connMu.Unlock()
	if c != nil {
		msg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
		_ = c.WriteControl(websocket.CloseMessage, msg, time.Now().Add(time.Second))
	}
	s.cancel(errShutdown)
}

// --- connection management ---

func (s *session) setConn(c *websocket.Conn) {
	s.connMu.Lock()
	old := s.conn
	s.conn = c
	s.connMu.Unlock()
	if old != nil {
		_ = old.Close()
	}
}

func (s *session) getConn() *websocket.Conn {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.conn
}

func (s *session) closeConn() {
	if c := s.getConn(); c != nil {
		_ = c.Close()
	}
}

func isPresigned(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	q := u.Query()
	for _, p := range []string{"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Signature"} {
		if q.Has(p) {
			return true
		}
	}
	return false
}

func (s *session) dial(streamURL, token string) (*websocket.Conn, error) {
	ctx := s.ctx
	header := http.Header{}
	if s.opts.Credentials != nil && !isPresigned(streamURL) {
		creds, err := s.opts.Credentials.Retrieve(ctx)
		if err != nil {
			return nil, fmt.Errorf("retrieving credentials to sign data channel request: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, streamURL, nil)
		if err != nil {
			return nil, err
		}
		if err := v4.NewSigner().SignHTTP(ctx, creds, req, emptyPayloadHash, signingService, s.opts.Region, time.Now()); err != nil {
			return nil, fmt.Errorf("signing data channel request: %w", err)
		}
		header = req.Header
	}

	c, resp, err := s.dialer.DialContext(ctx, streamURL, header)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("opening data channel: %w (HTTP %s)", err, resp.Status)
		}
		return nil, fmt.Errorf("opening data channel: %w", err)
	}
	c.SetPongHandler(func(string) error {
		return c.SetReadDeadline(time.Now().Add(pongTimeout))
	})

	open, _ := json.Marshal(ssmproto.OpenDataChannelInput{
		MessageSchemaVersion: "1.0",
		RequestID:            uuid.NewString(),
		TokenValue:           token,
		ClientID:             s.clientID,
		ClientVersion:        ClientVersion,
	})
	_ = c.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := c.WriteMessage(websocket.TextMessage, open); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("sending data channel token: %w", err)
	}
	return c, nil
}

func (s *session) dialWithRetry(streamURL, token string) (*websocket.Conn, error) {
	var lastErr error
	delay := 100 * time.Millisecond
	for attempt := 0; attempt < 5; attempt++ {
		c, err := s.dial(streamURL, token)
		if err == nil {
			return c, nil
		}
		lastErr = err
		s.log.Debug("data channel dial failed", "attempt", attempt+1, "error", err)
		if !s.sleep(delay) {
			return nil, s.result()
		}
		delay = min(delay*2, 5*time.Second)
	}
	return nil, lastErr
}

// reconnect resumes the session on a new websocket after the current one fails.
func (s *session) reconnect() (*websocket.Conn, error) {
	if s.opts.Resume == nil {
		return nil, errors.New("data channel connection lost")
	}
	deadline := time.Now().Add(reconnectTimeout)
	delay := 200 * time.Millisecond
	for {
		token, newURL, err := s.opts.Resume(s.ctx)
		if err == nil && token == "" {
			return nil, ErrSessionExpired
		}
		if err == nil {
			s.connMu.Lock()
			if newURL != "" {
				s.streamURL = newURL
			}
			streamURL := s.streamURL
			s.connMu.Unlock()
			var c *websocket.Conn
			if c, err = s.dial(streamURL, token); err == nil {
				return c, nil
			}
		}
		s.log.Warn("resuming session failed", "error", err)
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("resuming session: %w", err)
		}
		if !s.sleep(delay) {
			return nil, s.result()
		}
		delay = min(delay*2, 5*time.Second)
	}
}

func (s *session) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-s.ctx.Done():
		return false
	}
}

func (s *session) writeRaw(raw []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	c := s.getConn()
	if c == nil {
		return errors.New("not connected")
	}
	_ = c.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := c.WriteMessage(websocket.BinaryMessage, raw); err != nil {
		// Closing the connection makes the reader notice and start a resume. Unacknowledged
		// messages are retransmitted on the new connection.
		s.log.Debug("data channel write failed", "error", err)
		_ = c.Close()
		return err
	}
	return nil
}

func (s *session) pingLoop() {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			if c := s.getConn(); c != nil {
				_ = c.WriteControl(websocket.PingMessage, []byte("keepalive"), time.Now().Add(writeTimeout))
			}
		}
	}
}

// --- outgoing stream ---

// send queues a stream data message. Data messages wait for flow control; control messages
// (handshake responses, flags) bypass it so the reader goroutine never blocks on itself.
func (s *session) send(pt ssmproto.PayloadType, payload []byte, control bool) error {
	s.mu.Lock()
	for !control && (s.paused || s.unacked.Len() >= sendWindow) && s.ctx.Err() == nil {
		s.cond.Wait()
	}
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return context.Cause(s.ctx)
	}
	if s.enc != nil && pt == ssmproto.PayloadOutput {
		var err error
		if payload, err = s.enc.Encrypt(payload); err != nil {
			s.mu.Unlock()
			return fmt.Errorf("encrypting input: %w", err)
		}
	}
	m := ssmproto.NewMessage(ssmproto.MsgInputStreamData, s.nextSeq, ssmproto.HeaderFlagData, pt, payload)
	s.nextSeq++
	raw := m.Marshal()
	now := time.Now()
	s.unacked.PushBack(&outMsg{seq: m.SequenceNumber, raw: raw, firstSent: now, lastSent: now})
	s.mu.Unlock()

	_ = s.writeRaw(raw)
	return nil
}

func (s *session) sendFlag(flag uint32) error {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, flag)
	return s.send(ssmproto.PayloadFlag, b, true)
}

func (s *session) handleAck(seq int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for e := s.unacked.Front(); e != nil; e = e.Next() {
		om := e.Value.(*outMsg)
		if om.seq != seq {
			continue
		}
		// Karn's algorithm: only sample round trips of messages sent once.
		if !om.resent {
			s.updateRTO(time.Since(om.firstSent))
		}
		s.unacked.Remove(e)
		s.cond.Broadcast()
		return
	}
}

// updateRTO applies the RFC 6298 estimator used by session-manager-plugin.
func (s *session) updateRTO(sample time.Duration) {
	const alpha, beta = 1.0 / 8.0, 1.0 / 4.0
	r := float64(sample)
	s.rttVar = (1-beta)*s.rttVar + beta*math.Abs(s.rtt-r)
	s.rtt = (1-alpha)*s.rtt + alpha*r
	s.rto = min(time.Duration(s.rtt+math.Max(float64(clockGranularity), 4*s.rttVar)), maxRTO)
}

func (s *session) retransmitLoop() {
	t := time.NewTicker(resendInterval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
		}
		if err := s.retransmit(false); err != nil {
			s.fail(err)
			return
		}
	}
}

// retransmit resends unacknowledged messages whose timeout has passed, or all of them when all
// is set (after a reconnect, when anything in flight may have been lost).
func (s *session) retransmit(all bool) error {
	now := time.Now()
	var batch [][]byte
	s.mu.Lock()
	for e := s.unacked.Front(); e != nil; e = e.Next() {
		om := e.Value.(*outMsg)
		if !all && now.Sub(om.lastSent) < s.rto {
			continue
		}
		if now.Sub(om.firstSent) > resendTimeout {
			s.mu.Unlock()
			return fmt.Errorf("message %d was not acknowledged within %s", om.seq, resendTimeout)
		}
		om.lastSent = now
		om.resent = true
		batch = append(batch, om.raw)
	}
	s.mu.Unlock()
	for _, raw := range batch {
		if err := s.writeRaw(raw); err != nil {
			break
		}
	}
	return nil
}

func (s *session) setPaused(p bool) {
	s.mu.Lock()
	s.paused = p
	s.cond.Broadcast()
	s.mu.Unlock()
}

// waitDrained waits until every outgoing message has been acknowledged.
func (s *session) waitDrained(timeout time.Duration) bool {
	timedOut := false
	t := time.AfterFunc(timeout, func() {
		s.mu.Lock()
		timedOut = true
		s.cond.Broadcast()
		s.mu.Unlock()
	})
	defer t.Stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.unacked.Len() > 0 && !timedOut && s.ctx.Err() == nil {
		s.cond.Wait()
	}
	return s.unacked.Len() == 0
}

func (s *session) pumpInput(in io.Reader) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := in.Read(buf)
		for off := 0; off < n; off += maxPayloadSize {
			chunk := append([]byte(nil), buf[off:min(off+maxPayloadSize, n)]...)
			if serr := s.send(ssmproto.PayloadOutput, chunk, false); serr != nil {
				return serr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// finishInput flushes outstanding input and asks the agent to end the session.
func (s *session) finishInput() {
	if !s.waitDrained(drainTimeout) {
		s.log.Debug("timed out waiting for input to be acknowledged")
	}
	s.mu.Lock()
	agentVer := s.agentVer
	s.mu.Unlock()
	if agentVer != "" && !versionAtLeast(agentVer, terminateFlagMinAgentVersion) {
		return
	}
	if err := s.sendFlag(ssmproto.FlagTerminateSession); err == nil {
		s.waitDrained(terminateAckWait)
	}
}

// --- incoming stream ---

func (s *session) writeOutput(out io.Writer) {
	defer close(s.outputDone)
	for p := range s.outCh {
		if _, err := out.Write(p); err != nil {
			s.fail(fmt.Errorf("writing output: %w", err))
			return
		}
	}
}

func (s *session) readLoop() {
	defer close(s.outCh)
	for {
		c := s.getConn()
		if c == nil {
			return
		}
		_, data, err := c.ReadMessage()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			s.log.Warn("data channel connection lost, resuming session", "error", err)
			nc, rerr := s.reconnect()
			if rerr != nil {
				s.fail(rerr)
				return
			}
			s.setConn(nc)
			s.log.Info("session resumed")
			if err := s.retransmit(true); err != nil {
				s.fail(err)
				return
			}
			continue
		}
		closed, err := s.handleFrame(data)
		if err != nil {
			s.fail(err)
			return
		}
		if closed {
			return
		}
	}
}

// handleFrame processes one websocket frame. It reports whether the agent closed the channel.
func (s *session) handleFrame(data []byte) (bool, error) {
	m, err := ssmproto.UnmarshalMessage(data)
	if err != nil {
		s.log.Debug("discarding invalid frame", "error", err)
		return false, nil
	}
	switch m.MessageType {
	case ssmproto.MsgOutputStreamData:
		return false, s.handleOutput(m)
	case ssmproto.MsgAcknowledge:
		var ack ssmproto.AcknowledgeContent
		if err := json.Unmarshal(m.Payload, &ack); err != nil {
			s.log.Debug("discarding invalid acknowledge", "error", err)
			return false, nil
		}
		s.handleAck(ack.SequenceNumber)
	case ssmproto.MsgChannelClosed:
		var cc ssmproto.ChannelClosed
		_ = json.Unmarshal(m.Payload, &cc)
		s.log.Debug("channel closed by agent", "output", cc.Output)
		if cc.Output != "" {
			fmt.Fprintln(s.stderr, cc.Output)
		}
		return true, nil
	case ssmproto.MsgStartPublication:
		s.setPaused(false)
	case ssmproto.MsgPausePublication:
		s.setPaused(true)
	default:
		s.log.Debug("ignoring message", "type", m.MessageType)
	}
	return false, nil
}

func (s *session) handleOutput(m *ssmproto.Message) error {
	switch {
	case m.SequenceNumber < s.expectedSeq:
		// A retransmission of something already delivered: our ack was probably lost.
		s.sendAck(m)
		return nil
	case m.SequenceNumber > s.expectedSeq:
		if len(s.pending) < incomingBufferCap {
			s.pending[m.SequenceNumber] = m
			s.sendAck(m)
		}
		return nil
	}

	if err := s.process(m); err != nil {
		return err
	}
	s.expectedSeq++
	for {
		next, ok := s.pending[s.expectedSeq]
		if !ok {
			return nil
		}
		delete(s.pending, s.expectedSeq)
		if err := s.process(next); err != nil {
			return err
		}
		s.expectedSeq++
	}
}

// process handles an in-order output message. Messages buffered out of order were acknowledged
// on arrival; acknowledging them again here is harmless.
func (s *session) process(m *ssmproto.Message) error {
	switch m.PayloadType {
	case ssmproto.PayloadHandshakeRequest:
		s.sendAck(m)
		return s.handleHandshakeRequest(m.Payload)
	case ssmproto.PayloadHandshakeComplete:
		s.sendAck(m)
		var hc ssmproto.HandshakeComplete
		if err := json.Unmarshal(m.Payload, &hc); err != nil {
			return fmt.Errorf("decoding handshake complete: %w", err)
		}
		if hc.CustomerMessage != "" {
			fmt.Fprintln(s.stderr, hc.CustomerMessage)
		}
		s.log.Debug("session handshake complete")
		s.handshakeOnce.Do(func() { close(s.handshakeDone) })
		return nil
	case ssmproto.PayloadEncChallengeRequest:
		s.sendAck(m)
		return s.handleEncryptionChallenge(m.Payload)
	case ssmproto.PayloadOutput, ssmproto.PayloadStdErr, ssmproto.PayloadExitCode:
		payload := m.Payload
		if s.enc != nil {
			var err error
			if payload, err = s.enc.Decrypt(payload); err != nil {
				return fmt.Errorf("decrypting output: %w", err)
			}
		}
		switch m.PayloadType {
		case ssmproto.PayloadOutput:
			// Agents that predate the handshake go straight to data.
			s.handshakeOnce.Do(func() { close(s.handshakeDone) })
			select {
			case s.outCh <- payload:
			case <-s.ctx.Done():
				return nil
			}
		case ssmproto.PayloadStdErr:
			_, _ = s.stderr.Write(payload)
		default:
			s.log.Debug("remote exit code", "code", strings.TrimSpace(string(payload)))
		}
		s.sendAck(m)
		return nil
	case ssmproto.PayloadFlag:
		s.sendAck(m)
		if len(m.Payload) >= 4 && binary.BigEndian.Uint32(m.Payload) == ssmproto.FlagConnectToPortError {
			return errors.New("the SSM agent could not connect to the requested port on the instance")
		}
		return nil
	default:
		s.sendAck(m)
		s.log.Debug("ignoring payload", "type", m.PayloadType)
		return nil
	}
}

func (s *session) sendAck(m *ssmproto.Message) {
	b, _ := json.Marshal(ssmproto.AcknowledgeContent{
		MessageType:         m.MessageType,
		MessageID:           m.MessageID.String(),
		SequenceNumber:      m.SequenceNumber,
		IsSequentialMessage: true,
	})
	_ = s.writeRaw(ssmproto.NewMessage(ssmproto.MsgAcknowledge, 0, ssmproto.HeaderFlagAck, 0, b).Marshal())
}

func (s *session) handleHandshakeRequest(payload []byte) error {
	var req ssmproto.HandshakeRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return fmt.Errorf("decoding handshake request: %w", err)
	}
	s.log.Debug("handshake request", "agentVersion", req.AgentVersion)
	s.mu.Lock()
	s.agentVer = req.AgentVersion
	s.mu.Unlock()

	resp := ssmproto.HandshakeResponse{ClientVersion: ClientVersion, ProcessedClientActions: []ssmproto.ProcessedClientAction{}}
	var errs []error
	for _, action := range req.RequestedClientActions {
		pa := ssmproto.ProcessedClientAction{ActionType: action.ActionType, ActionStatus: ssmproto.ActionSuccess}
		var err error
		switch action.ActionType {
		case ssmproto.ActionSessionType:
			var st ssmproto.SessionTypeRequest
			if err = json.Unmarshal(action.ActionParameters, &st); err == nil && st.SessionType != ssmproto.SessionTypePort {
				err = fmt.Errorf("unsupported session type %q (only %q sessions can carry SSH)", st.SessionType, ssmproto.SessionTypePort)
			}
		case ssmproto.ActionKMSEncryption:
			var kr ssmproto.KMSEncryptionRequest
			if err = json.Unmarshal(action.ActionParameters, &kr); err == nil {
				var enc *ssmproto.Encrypter
				if enc, err = newKMSEncrypter(s.ctx, s.opts.KMS, kr.KMSKeyID, s.opts.SessionID, s.opts.TargetID); err == nil {
					pa.ActionResult = ssmproto.KMSEncryptionResponse{KMSCipherTextKey: enc.CipherTextKey}
					s.mu.Lock()
					s.enc = enc
					s.mu.Unlock()
					s.log.Debug("session encryption enabled", "kmsKeyId", kr.KMSKeyID)
				}
			}
		default:
			pa.ActionStatus = ssmproto.ActionUnsupported
			err = fmt.Errorf("unsupported handshake action %s", action.ActionType)
		}
		if err != nil {
			if pa.ActionStatus == ssmproto.ActionSuccess {
				pa.ActionStatus = ssmproto.ActionFailed
			}
			pa.Error = fmt.Sprintf("Failed to process action %s: %s", action.ActionType, err)
			resp.Errors = append(resp.Errors, err.Error())
			errs = append(errs, err)
		}
		resp.ProcessedClientActions = append(resp.ProcessedClientActions, pa)
	}

	b, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	if err := s.send(ssmproto.PayloadHandshakeResponse, b, true); err != nil {
		return err
	}
	if len(errs) > 0 {
		return fmt.Errorf("session handshake failed: %w", errors.Join(errs...))
	}
	return nil
}

func (s *session) handleEncryptionChallenge(payload []byte) error {
	if s.enc == nil {
		return errors.New("agent sent an encryption challenge but encryption was not negotiated")
	}
	var req ssmproto.EncryptionChallenge
	if err := json.Unmarshal(payload, &req); err != nil {
		return fmt.Errorf("decoding encryption challenge: %w", err)
	}
	plain, err := s.enc.Decrypt(req.Challenge)
	if err != nil {
		return fmt.Errorf("decrypting encryption challenge: %w", err)
	}
	resp, err := s.enc.Encrypt(plain)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(ssmproto.EncryptionChallenge{Challenge: resp})
	return s.send(ssmproto.PayloadEncChallengeResponse, b, true)
}

// versionAtLeast compares dotted numeric versions. Unparseable versions compare as new enough.
func versionAtLeast(v, minimum string) bool {
	a, b := strings.Split(v, "."), strings.Split(minimum, ".")
	for i := 0; i < max(len(a), len(b)); i++ {
		var x, y int
		var err error
		if i < len(a) {
			if x, err = strconv.Atoi(a[i]); err != nil {
				return true
			}
		}
		if i < len(b) {
			y, _ = strconv.Atoi(b[i])
		}
		if x != y {
			return x > y
		}
	}
	return true
}
