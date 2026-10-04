// Package fakeaws provides test doubles for the AWS side of an SSM session: a data channel
// endpoint that behaves like the SSM agent, and minimal EC2, SSM and KMS APIs.
package fakeaws

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/gorilla/websocket"

	"github.com/wrouesnel/ssm-proxycommand/pkg/ssmproto"
)

// InitialToken is the token the agent accepts for the first connection.
const InitialToken = "initial-token"

// Agent emulates the AWS side of a Session Manager "Port" session: it speaks the data channel
// protocol over a websocket and bridges the stream to a TCP target, as the SSM agent does.
type Agent struct {
	// Target is the TCP address standing in for the port on the instance.
	Target string
	// SessionType is requested during the handshake. Defaults to "Port".
	SessionType string
	// DataKey, when set, makes the agent require KMS encryption using this 64 byte key.
	DataKey []byte

	// Fault injection, applied to stream data only.
	DropInput  float64 // probability of ignoring an incoming data message
	DropOutput float64 // probability of not sending an outgoing message on its first attempt
	DupOutput  float64 // probability of sending an outgoing message twice
	KillAfter  int     // close the websocket once after this many outgoing frames

	srv *httptest.Server
	rnd *rand.Rand

	mu          sync.Mutex
	conn        *websocket.Conn
	tokens      map[string]bool
	connections int
	framesOut   int
	killed      bool
	nextSeq     int64
	unacked     map[int64][]byte
	expectedSeq int64
	pending     map[int64]*ssmproto.Message
	targetConn  net.Conn
	enc         *ssmproto.Encrypter // encrypts with the client's decryption key
	terminated  bool
	errs        []string
	done        chan struct{}
}

// NewAgent returns an agent that forwards to target. Call Start before use.
func NewAgent(target string) *Agent {
	return &Agent{
		Target:      target,
		SessionType: ssmproto.SessionTypePort,
		rnd:         rand.New(rand.NewPCG(1, 2)),
		tokens:      map[string]bool{InitialToken: true},
		unacked:     map[int64][]byte{},
		pending:     map[int64]*ssmproto.Message{},
		done:        make(chan struct{}),
	}
}

// Start begins serving the data channel.
func (a *Agent) Start() {
	a.srv = httptest.NewServer(http.HandlerFunc(a.serve))
	go a.resendLoop()
}

// Close stops the agent.
func (a *Agent) Close() {
	select {
	case <-a.done:
	default:
		close(a.done)
	}
	a.srv.Close()
	a.mu.Lock()
	if a.targetConn != nil {
		a.targetConn.Close()
	}
	a.mu.Unlock()
}

// URL is the stream URL to hand the client.
func (a *Agent) URL() string {
	return "ws" + strings.TrimPrefix(a.srv.URL, "http") + "/v1/data-channel/sess-1"
}

// Errors returns protocol violations the agent saw from the client.
func (a *Agent) Errors() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.errs...)
}

// Connections is the number of websocket connections accepted so far.
func (a *Agent) Connections() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.connections
}

// Terminated reports whether the client sent the TerminateSession flag.
func (a *Agent) Terminated() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.terminated
}

// Resume issues a new single-use token for the session, as ssm:ResumeSession does.
func (a *Agent) Resume(ctx context.Context) (string, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	tok := fmt.Sprintf("resume-token-%d", len(a.tokens)+a.connections)
	a.tokens[tok] = true
	return tok, "", nil
}

func (a *Agent) errorf(format string, args ...any) {
	a.mu.Lock()
	a.errs = append(a.errs, fmt.Sprintf(format, args...))
	a.mu.Unlock()
}

var upgrader = websocket.Upgrader{}

func (a *Agent) serve(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()

	mt, data, err := c.ReadMessage()
	if err != nil || mt != websocket.TextMessage {
		a.errorf("expected text open message, got %d %v", mt, err)
		return
	}
	var open ssmproto.OpenDataChannelInput
	if err := json.Unmarshal(data, &open); err != nil {
		a.errorf("bad open message: %v", err)
		return
	}
	a.mu.Lock()
	if !a.tokens[open.TokenValue] {
		a.mu.Unlock()
		a.errorf("invalid token %q", open.TokenValue)
		return
	}
	delete(a.tokens, open.TokenValue)
	a.conn = c
	a.connections++
	first := a.connections == 1
	// Anything unacknowledged on the old connection is resent on the new one.
	for seq := int64(0); seq < a.nextSeq; seq++ {
		if raw, ok := a.unacked[seq]; ok {
			_ = c.WriteMessage(websocket.BinaryMessage, raw)
		}
	}
	a.mu.Unlock()

	if first {
		a.sendHandshakeRequest()
	}

	for {
		_, data, err := c.ReadMessage()
		if err != nil {
			return
		}
		m, err := ssmproto.UnmarshalMessage(data)
		if err != nil {
			a.errorf("client sent invalid frame: %v", err)
			return
		}
		switch m.MessageType {
		case ssmproto.MsgAcknowledge:
			var ack ssmproto.AcknowledgeContent
			if err := json.Unmarshal(m.Payload, &ack); err != nil {
				a.errorf("bad ack: %v", err)
				continue
			}
			a.mu.Lock()
			delete(a.unacked, ack.SequenceNumber)
			a.mu.Unlock()
		case ssmproto.MsgInputStreamData:
			a.handleInput(m)
		default:
			a.errorf("unexpected client message type %q", m.MessageType)
		}
	}
}

func (a *Agent) handleInput(m *ssmproto.Message) {
	a.mu.Lock()
	if m.PayloadType == ssmproto.PayloadOutput && a.rnd.Float64() < a.DropInput {
		a.mu.Unlock()
		return
	}
	a.ackLocked(m)
	if m.SequenceNumber < a.expectedSeq {
		a.mu.Unlock()
		return
	}
	a.pending[m.SequenceNumber] = m
	var ready []*ssmproto.Message
	for {
		next, ok := a.pending[a.expectedSeq]
		if !ok {
			break
		}
		delete(a.pending, a.expectedSeq)
		a.expectedSeq++
		ready = append(ready, next)
	}
	a.mu.Unlock()
	for _, r := range ready {
		a.processInput(r)
	}
}

func (a *Agent) processInput(m *ssmproto.Message) {
	switch m.PayloadType {
	case ssmproto.PayloadHandshakeResponse:
		var resp ssmproto.HandshakeResponse
		if err := json.Unmarshal(m.Payload, &resp); err != nil {
			a.errorf("bad handshake response: %v", err)
			return
		}
		if len(resp.Errors) > 0 {
			// The real agent gives up on the session here.
			a.sendChannelClosed("handshake failed")
			return
		}
		if a.DataKey != nil {
			var kr ssmproto.KMSEncryptionResponse
			for _, pa := range resp.ProcessedClientActions {
				if pa.ActionType == ssmproto.ActionKMSEncryption {
					b, _ := json.Marshal(pa.ActionResult)
					_ = json.Unmarshal(b, &kr)
				}
			}
			if string(kr.KMSCipherTextKey) != "wrapped-key" {
				a.errorf("unexpected KMS ciphertext key %q", kr.KMSCipherTextKey)
			}
			// The agent encrypts with the half the client decrypts with, and vice versa.
			half := len(a.DataKey) / 2
			swapped := append(append([]byte{}, a.DataKey[half:]...), a.DataKey[:half]...)
			enc, _ := ssmproto.NewEncrypter(swapped, nil)
			a.mu.Lock()
			a.enc = enc
			a.mu.Unlock()
			challenge, _ := enc.Encrypt([]byte("challenge-bytes"))
			b, _ := json.Marshal(ssmproto.EncryptionChallenge{Challenge: challenge})
			a.sendOutput(ssmproto.PayloadEncChallengeRequest, b)
			return
		}
		a.completeHandshake()
	case ssmproto.PayloadEncChallengeResponse:
		var ch ssmproto.EncryptionChallenge
		_ = json.Unmarshal(m.Payload, &ch)
		plain, err := a.encrypter().Decrypt(ch.Challenge)
		if err != nil || string(plain) != "challenge-bytes" {
			a.errorf("encryption challenge failed: %v %q", err, plain)
			return
		}
		a.completeHandshake()
	case ssmproto.PayloadOutput:
		payload := m.Payload
		if enc := a.encrypter(); enc != nil {
			var err error
			if payload, err = enc.Decrypt(payload); err != nil {
				a.errorf("decrypting input: %v", err)
				return
			}
		}
		a.mu.Lock()
		tc := a.targetConn
		a.mu.Unlock()
		if tc == nil {
			a.errorf("data before target connected")
			return
		}
		_, _ = tc.Write(payload)
	case ssmproto.PayloadFlag:
		if binary.BigEndian.Uint32(m.Payload) == ssmproto.FlagTerminateSession {
			a.mu.Lock()
			a.terminated = true
			tc := a.targetConn
			a.mu.Unlock()
			if tc != nil {
				tc.Close()
			}
		}
	default:
		a.errorf("unexpected input payload type %d", m.PayloadType)
	}
}

func (a *Agent) encrypter() *ssmproto.Encrypter {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.enc
}

func (a *Agent) sendHandshakeRequest() {
	params, _ := json.Marshal(ssmproto.SessionTypeRequest{SessionType: a.SessionType, Properties: map[string]string{"portNumber": "22"}})
	req := ssmproto.HandshakeRequest{
		AgentVersion:           "3.3.0.0",
		RequestedClientActions: []ssmproto.RequestedClientAction{{ActionType: ssmproto.ActionSessionType, ActionParameters: params}},
	}
	if a.DataKey != nil {
		kp, _ := json.Marshal(ssmproto.KMSEncryptionRequest{KMSKeyID: "alias/test"})
		req.RequestedClientActions = append(req.RequestedClientActions, ssmproto.RequestedClientAction{ActionType: ssmproto.ActionKMSEncryption, ActionParameters: kp})
	}
	b, _ := json.Marshal(req)
	a.sendOutput(ssmproto.PayloadHandshakeRequest, b)
}

func (a *Agent) completeHandshake() {
	tc, err := net.Dial("tcp", a.Target)
	if err != nil {
		a.errorf("dialing target: %v", err)
		return
	}
	a.mu.Lock()
	a.targetConn = tc
	a.mu.Unlock()
	b, _ := json.Marshal(ssmproto.HandshakeComplete{HandshakeTimeToComplete: time.Millisecond})
	a.sendOutput(ssmproto.PayloadHandshakeComplete, b)
	go a.pumpTarget(tc)
}

func (a *Agent) pumpTarget(tc net.Conn) {
	buf := make([]byte, 1024)
	for {
		n, err := tc.Read(buf)
		if n > 0 {
			payload := append([]byte(nil), buf[:n]...)
			if enc := a.encrypter(); enc != nil {
				payload, _ = enc.Encrypt(payload)
			}
			a.sendOutput(ssmproto.PayloadOutput, payload)
		}
		if err != nil {
			break
		}
	}
	if a.Terminated() {
		return
	}
	// The remote end closed: flush, then close the channel like the agent does.
	for i := 0; i < 500; i++ {
		a.mu.Lock()
		n := len(a.unacked)
		a.mu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.sendChannelClosed("")
}

func (a *Agent) sendChannelClosed(output string) {
	b, _ := json.Marshal(ssmproto.ChannelClosed{SessionID: "sess-1", MessageType: ssmproto.MsgChannelClosed, Output: output})
	a.write(ssmproto.NewMessage(ssmproto.MsgChannelClosed, 0, 0, 0, b).Marshal())
}

func (a *Agent) sendOutput(pt ssmproto.PayloadType, payload []byte) {
	a.mu.Lock()
	m := ssmproto.NewMessage(ssmproto.MsgOutputStreamData, a.nextSeq, ssmproto.HeaderFlagData, pt, payload)
	a.nextSeq++
	raw := m.Marshal()
	a.unacked[m.SequenceNumber] = raw
	isData := pt == ssmproto.PayloadOutput
	drop := isData && a.rnd.Float64() < a.DropOutput
	dup := isData && a.rnd.Float64() < a.DupOutput
	a.mu.Unlock()
	if drop {
		return
	}
	a.write(raw)
	if dup {
		a.write(raw)
	}
}

func (a *Agent) write(raw []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.conn == nil {
		return
	}
	_ = a.conn.WriteMessage(websocket.BinaryMessage, raw)
	a.framesOut++
	if a.KillAfter > 0 && !a.killed && a.framesOut >= a.KillAfter {
		a.killed = true
		a.conn.Close()
		a.conn = nil
	}
}

func (a *Agent) ackLocked(m *ssmproto.Message) {
	b, _ := json.Marshal(ssmproto.AcknowledgeContent{MessageType: m.MessageType, MessageID: m.MessageID.String(), SequenceNumber: m.SequenceNumber, IsSequentialMessage: true})
	if a.conn != nil {
		_ = a.conn.WriteMessage(websocket.BinaryMessage, ssmproto.NewMessage(ssmproto.MsgAcknowledge, 0, ssmproto.HeaderFlagAck, 0, b).Marshal())
	}
}

func (a *Agent) resendLoop() {
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-a.done:
			return
		case <-t.C:
		}
		a.mu.Lock()
		if a.conn != nil {
			for seq := int64(0); seq < a.nextSeq; seq++ {
				if raw, ok := a.unacked[seq]; ok {
					_ = a.conn.WriteMessage(websocket.BinaryMessage, raw)
				}
			}
		}
		a.mu.Unlock()
	}
}

// KMS returns a fixed data key, standing in for kms:GenerateDataKey.
type KMS struct {
	Key []byte
	// Check, if set, inspects each request.
	Check func(*kms.GenerateDataKeyInput) error
}

func (f *KMS) GenerateDataKey(ctx context.Context, in *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	if f.Check != nil {
		if err := f.Check(in); err != nil {
			return nil, err
		}
	}
	return &kms.GenerateDataKeyOutput{Plaintext: f.Key, CiphertextBlob: []byte("wrapped-key")}, nil
}
