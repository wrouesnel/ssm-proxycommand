// Package ssmproto implements the wire format of the AWS Systems Manager Session Manager data
// channel: the binary client message framing, and the JSON payloads exchanged during the session
// handshake, including the AES-GCM payload encryption used when KMS encryption is enabled.
package ssmproto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Message types carried in the 32 byte MessageType header field.
const (
	MsgInputStreamData  = "input_stream_data"
	MsgOutputStreamData = "output_stream_data"
	MsgAcknowledge      = "acknowledge"
	MsgChannelClosed    = "channel_closed"
	MsgStartPublication = "start_publication"
	MsgPausePublication = "pause_publication"
)

// PayloadType identifies the contents of a stream data message.
type PayloadType uint32

const (
	PayloadOutput               PayloadType = 1
	PayloadError                PayloadType = 2
	PayloadSize                 PayloadType = 3
	PayloadParameter            PayloadType = 4
	PayloadHandshakeRequest     PayloadType = 5
	PayloadHandshakeResponse    PayloadType = 6
	PayloadHandshakeComplete    PayloadType = 7
	PayloadEncChallengeRequest  PayloadType = 8
	PayloadEncChallengeResponse PayloadType = 9
	PayloadFlag                 PayloadType = 10
	PayloadStdErr               PayloadType = 11
	PayloadExitCode             PayloadType = 12
)

// Flag values sent as a big-endian uint32 in a PayloadFlag message.
const (
	FlagDisconnectToPort   uint32 = 1
	FlagTerminateSession   uint32 = 2
	FlagConnectToPortError uint32 = 3
)

// Message header flag values.
const (
	HeaderFlagData uint64 = 0
	HeaderFlagAck  uint64 = 3
)

// Binary layout of a client message. HeaderLength counts every field up to, but not including,
// PayloadLength.
const (
	offHeaderLength   = 0
	offMessageType    = offHeaderLength + 4
	offSchemaVersion  = offMessageType + 32
	offCreatedDate    = offSchemaVersion + 4
	offSequenceNumber = offCreatedDate + 8
	offFlags          = offSequenceNumber + 8
	offMessageID      = offFlags + 8
	offPayloadDigest  = offMessageID + 16
	offPayloadType    = offPayloadDigest + 32
	offPayloadLength  = offPayloadType + 4
	offPayload        = offPayloadLength + 4

	headerLength   = offPayloadLength
	messageTypeLen = 32
)

// Message is a single decoded data channel frame.
type Message struct {
	MessageType    string
	SchemaVersion  uint32
	CreatedDate    uint64
	SequenceNumber int64
	Flags          uint64
	MessageID      uuid.UUID
	PayloadType    PayloadType
	Payload        []byte
}

func NewMessage(messageType string, seq int64, flags uint64, payloadType PayloadType, payload []byte) *Message {
	return &Message{
		MessageType:    messageType,
		SchemaVersion:  1,
		CreatedDate:    uint64(time.Now().UnixMilli()),
		SequenceNumber: seq,
		Flags:          flags,
		MessageID:      uuid.New(),
		PayloadType:    payloadType,
		Payload:        payload,
	}
}

// Marshal encodes the message into its wire format.
func (m *Message) Marshal() []byte {
	b := make([]byte, offPayload+len(m.Payload))
	be := binary.BigEndian
	be.PutUint32(b[offHeaderLength:], headerLength)
	// The message type is space padded.
	copy(b[offMessageType:offSchemaVersion], bytes.Repeat([]byte{' '}, messageTypeLen))
	copy(b[offMessageType:offSchemaVersion], m.MessageType)
	be.PutUint32(b[offSchemaVersion:], m.SchemaVersion)
	be.PutUint64(b[offCreatedDate:], m.CreatedDate)
	be.PutUint64(b[offSequenceNumber:], uint64(m.SequenceNumber))
	be.PutUint64(b[offFlags:], m.Flags)
	putUUID(b[offMessageID:offPayloadDigest], m.MessageID)
	digest := sha256.Sum256(m.Payload)
	copy(b[offPayloadDigest:offPayloadType], digest[:])
	be.PutUint32(b[offPayloadType:], uint32(m.PayloadType))
	be.PutUint32(b[offPayloadLength:], uint32(len(m.Payload)))
	copy(b[offPayload:], m.Payload)
	return b
}

var errShortMessage = errors.New("message too short")

// UnmarshalMessage decodes and validates a wire format message.
func UnmarshalMessage(b []byte) (*Message, error) {
	if len(b) < offPayload {
		return nil, errShortMessage
	}
	be := binary.BigEndian
	m := &Message{
		MessageType:    strings.TrimSpace(string(bytes.Trim(b[offMessageType:offSchemaVersion], "\x00"))),
		SchemaVersion:  be.Uint32(b[offSchemaVersion:]),
		CreatedDate:    be.Uint64(b[offCreatedDate:]),
		SequenceNumber: int64(be.Uint64(b[offSequenceNumber:])),
		Flags:          be.Uint64(b[offFlags:]),
		MessageID:      getUUID(b[offMessageID:offPayloadDigest]),
		PayloadType:    PayloadType(be.Uint32(b[offPayloadType:])),
	}
	// Publication control messages carry no meaningful header beyond their type.
	if m.MessageType == MsgStartPublication || m.MessageType == MsgPausePublication {
		return m, nil
	}

	hl := int(be.Uint32(b[offHeaderLength:]))
	if hl == 0 {
		return nil, errors.New("header length is zero")
	}
	if hl+4 > len(b) {
		return nil, errShortMessage
	}
	payloadLen := int(be.Uint32(b[hl:]))
	start := hl + 4
	if start+payloadLen > len(b) {
		return nil, fmt.Errorf("payload length %d exceeds message size %d", payloadLen, len(b))
	}
	m.Payload = b[start : start+payloadLen]
	if payloadLen != 0 {
		digest := sha256.Sum256(m.Payload)
		if !bytes.Equal(digest[:], b[offPayloadDigest:offPayloadType]) {
			return nil, errors.New("payload digest mismatch")
		}
	}
	return m, nil
}

// The protocol stores UUIDs as two big-endian longs, least significant half first.
func putUUID(b []byte, id uuid.UUID) {
	copy(b[0:8], id[8:16])
	copy(b[8:16], id[0:8])
}

func getUUID(b []byte) uuid.UUID {
	var id uuid.UUID
	copy(id[8:16], b[0:8])
	copy(id[0:8], b[8:16])
	return id
}

// AcknowledgeContent is the JSON payload of an acknowledge message.
type AcknowledgeContent struct {
	MessageType         string `json:"AcknowledgedMessageType"`
	MessageID           string `json:"AcknowledgedMessageId"`
	SequenceNumber      int64  `json:"AcknowledgedMessageSequenceNumber"`
	IsSequentialMessage bool   `json:"IsSequentialMessage"`
}

// ChannelClosed is the JSON payload of a channel_closed message.
type ChannelClosed struct {
	MessageID     string `json:"MessageId"`
	CreatedDate   string `json:"CreatedDate"`
	DestinationID string `json:"DestinationId"`
	SessionID     string `json:"SessionId"`
	MessageType   string `json:"MessageType"`
	SchemaVersion int    `json:"SchemaVersion"`
	Output        string `json:"Output"`
}

// OpenDataChannelInput is the first (text) frame sent on a new websocket.
type OpenDataChannelInput struct {
	MessageSchemaVersion string `json:"MessageSchemaVersion"`
	RequestID            string `json:"RequestId"`
	TokenValue           string `json:"TokenValue"`
	ClientID             string `json:"ClientId"`
	ClientVersion        string `json:"ClientVersion"`
}
