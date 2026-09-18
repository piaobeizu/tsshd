/*
MIT License

Copyright (c) 2024-2026 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package tsshd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/trzsz/kcp-go/v5"
	"github.com/trzsz/quic-go"
	"github.com/trzsz/smux"
)

const kNoErrorMsg = "_TSSHD_NO_ERROR_"

// ErrCode is an enumeration for tsshd public errors
type ErrCode int

const (
	// ErrProhibited is an error indicating administratively prohibited
	ErrProhibited ErrCode = 101
	// ErrNotPty indicates the session does not support PTY
	ErrNotPty ErrCode = 102
)

// String converts the error code to human readable form
func (c ErrCode) String() string {
	switch c {
	case ErrProhibited:
		return "ErrProhibited"
	case ErrNotPty:
		return "ErrNotPty"
	default:
		return fmt.Sprintf("ErrCode(%d)", c)
	}
}

// Error is an tsshd error
type Error struct {
	Code ErrCode
	Msg  string
}

// Error converts the tsshd error to human readable form
func (e *Error) Error() string {
	if e.Code == 0 {
		return e.Msg
	}
	return fmt.Sprintf("%s: %s", e.Code.String(), e.Msg)
}

// ServerInfo includes all information used for client login
type ServerInfo struct {
	ServerVer  string `json:",omitempty"`
	ProtoVer   int    `json:",omitempty"`
	Port       int    `json:",omitempty"`
	Mode       string `json:",omitempty"`
	Pass       string `json:",omitempty"`
	Salt       string `json:",omitempty"`
	ServerCert string `json:",omitempty"`
	ClientCert string `json:",omitempty"`
	ClientKey  string `json:",omitempty"`
	ProxyKey   string `json:",omitempty"`
	ClientID   uint64 `json:",omitempty"`
	ServerID   uint64 `json:",omitempty"`
	ProxyMode  string `json:",omitempty"`
	MTU        uint16 `json:",omitempty"`
}

type SessionInfo struct {
	ID    uint64 `json:",omitempty"`
	Title string `json:",omitempty"`
}

type BaseInfo struct {
	Time     int64         `json:",omitempty"`
	Name     string        `json:",omitempty"`
	Sessions []SessionInfo `json:",omitempty"`
}

type ServerItem struct {
	Pid  int    `json:",omitempty"`
	Info string `json:",omitempty"`
}

type errorMessage struct {
	Code ErrCode `json:",omitempty"`
	Msg  string  `json:",omitempty"`
}

type debugMessage struct {
	Msg  string `json:",omitempty"`
	Time int64  `json:",omitempty"`
}

type busMessage struct {
	ClientVer        string        `json:",omitempty"`
	ProtoVer         int           `json:",omitempty"`
	AliveTimeout     time.Duration `json:",omitempty"`
	IntervalTime     time.Duration `json:",omitempty"`
	HeartbeatTimeout time.Duration `json:",omitempty"`
	SessionName      string        `json:",omitempty"`
}

type busResponse struct {
	errorMessage
	NextSessionID uint64 `json:",omitempty"`
}

func (d *busResponse) getErrorMessage() *errorMessage {
	return &d.errorMessage
}

type x11RequestMessage struct {
	ChannelType      string `json:",omitempty"`
	SingleConnection bool   `json:",omitempty"`
	AuthProtocol     string `json:",omitempty"`
	AuthCookie       string `json:",omitempty"`
	ScreenNumber     uint32 `json:",omitempty"`
}

type agentRequestMessage struct {
	ChannelType string `json:",omitempty"`
}

type startMessage struct {
	ID     uint64               `json:",omitempty"`
	Pty    bool                 `json:",omitempty"`
	Shell  bool                 `json:",omitempty"`
	Name   string               `json:",omitempty"`
	Args   []string             `json:",omitempty"`
	Cols   int                  `json:",omitempty"`
	Rows   int                  `json:",omitempty"`
	Envs   map[string]string    `json:",omitempty"`
	X11    *x11RequestMessage   `json:",omitempty"`
	Agent  *agentRequestMessage `json:",omitempty"`
	Subs   string               `json:",omitempty"`
	Attach bool                 `json:",omitempty"`
	ErrID  uint64               `json:",omitempty"`
}

type exitMessage struct {
	ID       uint64 `json:",omitempty"`
	ExitCode int    `json:",omitempty"`
}

type quitMessage struct {
	Msg string `json:",omitempty"`
}

// detachAckMessage is the server's reply to the client's "detach" bus
// command. It carries no fields today; the acknowledgement itself is the
// signal that the server has detached the sessions the client owned (see
// handleDetachEvent in bus.go).
type detachAckMessage struct{}

type aliveMessage struct {
	Time int64 `json:",omitempty"`
}

type resizeMessage struct {
	ID     uint64 `json:",omitempty"`
	Cols   int    `json:",omitempty"`
	Rows   int    `json:",omitempty"`
	Redraw bool   `json:",omitempty"`
	Marker []byte `json:",omitempty"`
}

type stderrMessage struct {
	ID uint64 `json:",omitempty"`
}

type channelMessage struct {
	ChannelType string `json:",omitempty"`
	ID          uint64 `json:",omitempty"`
}

type dialMessage struct {
	Net     string        `json:",omitempty"`
	Addr    string        `json:",omitempty"`
	Timeout time.Duration `json:",omitempty"`
}

type dialResponse struct {
	errorMessage
	RemoteAddr *net.TCPAddr `json:",omitempty"`
}

func (d *dialResponse) getErrorMessage() *errorMessage {
	return &d.errorMessage
}

type listenMessage struct {
	Net  string `json:",omitempty"`
	Addr string `json:",omitempty"`
}

type acceptMessage struct {
	ID uint64 `json:",omitempty"`
}

type dialUdpMessage struct {
	Net     string        `json:",omitempty"`
	Addr    string        `json:",omitempty"`
	Timeout time.Duration `json:",omitempty"`
}

type dialUdpResponse struct {
	errorMessage
	ID uint64 `json:",omitempty"`
}

type listenUdpMessage struct {
	Net  string `json:",omitempty"`
	Addr string `json:",omitempty"`
}

type acceptUdpMessage struct {
	ID uint64 `json:",omitempty"`
}

func (d *dialUdpResponse) getErrorMessage() *errorMessage {
	return &d.errorMessage
}

type udpReadyMessage struct {
}

type discardMessage struct {
	// Legacy fields (unchanged wire behavior for old clients).
	DiscardMarker        []byte `json:",omitempty"`
	DiscardedInput       []byte `json:",omitempty"`
	DiscardedOutputLines uint64 `json:",omitempty"`
	DiscardedOutputBytes uint64 `json:",omitempty"`

	// Classified extension (tsshd#7, design doc §4.5): kind-classified,
	// epoch-attributed input-discard reports. Emitted only to
	// InputAck-negotiating clients, through the ordered bus sender;
	// classified reports carry COUNTS, never the discarded byte payload,
	// so every event stays a single smux frame (see orderedBusSender).
	Kind string `json:",omitempty"`
	// SessionID attributes the report to one session (one connection
	// carries multiple sessions).
	SessionID uint64 `json:",omitempty"`
	// Epoch is the epoch the report's discarded bytes are attributed to
	// (the epoch the boundary CLOSED - the pre-marker epoch - for
	// inputDiscardCompleted; the new epoch for inputBoundary).
	Epoch uint64 `json:",omitempty"`
	// DiscardedInputBytes is the non-marker count of the discarded input
	// prefix (the classified counterpart of the legacy DiscardedInput
	// bytes).
	DiscardedInputBytes uint64 `json:",omitempty"`
	// OutputStart/OutputEnd is the half-open [start, end) byte range of
	// the session's stdout output stream source coordinates shed by a
	// client-requested disposal (session-lifetime; populated by tsshd#8).
	OutputStart uint64 `json:",omitempty"`
	OutputEnd   uint64 `json:",omitempty"`
	// RequestInputOffset echoes the applied-coordinate offset of a shed
	// request; ShedStatus reports its admission (rejected/expired).
	RequestInputOffset uint64 `json:",omitempty"`
	ShedStatus         string `json:",omitempty"`
	// InFlightBytes is the writer-owned handoff backlog at report time
	// (the R7-W1 definition; see serverOutputForwarder.inFlightBytes).
	InFlightBytes uint64 `json:",omitempty"`
}

// Discard report kinds (design doc §4.5): only inputBoundary creates an
// epoch boundary and resets client R/D; completion/status/output reports
// never reset anything.
const (
	kDiscardKindInputBoundary  = "inputBoundary"
	kDiscardKindInputCompleted = "inputDiscardCompleted"
	kDiscardKindOutputShed     = "outputShed"
	kDiscardKindRequestStatus  = "requestStatus"
)

// ShedStatus values for discard reports carrying a request echo
// (tsshd#8's admission outcomes; the vocabulary lands with the schema).
const (
	kShedStatusRejected = "rejected"
	kShedStatusExpired  = "expired"
)

type settingsMessage struct {
	KeepPendingInput  *bool `json:",omitempty"`
	KeepPendingOutput *bool `json:",omitempty"`
	// InputAck is the client's capability advertisement for the
	// input-ACCEPTED ack (tsshd#7): when true, the server emits input_ack
	// events and kind-classified discard reports on the bus stream. Old
	// servers ignore the unknown field; old clients never send it.
	InputAck *bool `json:",omitempty"`
}

// inputAckMessage is the server's "inputAck" bus event: the ordered count
// of non-marker input bytes of one session within one epoch that have been
// accepted by the PTY - writeAll returned on every server input write path
// (the normal forwardInput loop AND discardPendingInput's surviving-suffix
// write). "Accepted", never "application-handled". Acks are advisory: loss
// renders "no confirmation" and never stalls forwardInput.
type inputAckMessage struct {
	SessionID    uint64 `json:",omitempty"`
	Epoch        uint64 `json:",omitempty"`
	AppliedBytes uint64 `json:",omitempty"`
	WriteMS      int64  `json:",omitempty"`
}

// startResponse is the session-start/attach success response: the legacy
// errorMessage shape plus the additive Epoch field, the eager channel of
// the input-ack coordinate contract (design doc §4.5). Old clients parse it
// as errorMessage and ignore the extra field; an old server sends no Epoch,
// which a new client reads as "feature unsupported".
type startResponse struct {
	errorMessage
	Epoch uint64 `json:",omitempty"`
}

func (d *startResponse) getErrorMessage() *errorMessage {
	return &d.errorMessage
}

type errorResponder interface {
	getErrorMessage() *errorMessage
}

type rekeyMessage struct {
	PubKey []byte `json:",omitempty"`
}

type viewMessage struct {
	ID uint64 `json:",omitempty"`
}

func writeAll(dst io.Writer, data []byte) error {
	m := 0
	l := len(data)
	for m < l {
		n, err := dst.Write(data[m:])
		if err != nil {
			return err
		}
		m += n
	}
	return nil
}

func sendCommand(stream io.Writer, command string) error {
	if len(command) == 0 {
		return fmt.Errorf("send command is empty")
	}
	if len(command) > 255 {
		return fmt.Errorf("send command too long: %s", command)
	}
	buffer := make([]byte, len(command)+1)
	buffer[0] = uint8(len(command))
	copy(buffer[1:], []byte(command))
	if err := writeAll(stream, buffer); err != nil {
		return fmt.Errorf("send command write buffer failed: %w", err)
	}
	return nil
}

func recvCommand(stream io.Reader) (string, error) {
	length := make([]byte, 1)
	if _, err := stream.Read(length); err != nil {
		return "", fmt.Errorf("recv command read length failed: %w", err)
	}
	command := make([]byte, length[0])
	if _, err := io.ReadFull(stream, command); err != nil {
		return "", fmt.Errorf("recv command read buffer failed: %w", err)
	}
	return string(command), nil
}

func sendMessage(stream Stream, msg any) error {
	msgBuf, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("send message marshal failed: %w", err)
	}
	buffer := make([]byte, len(msgBuf)+4)
	binary.BigEndian.PutUint32(buffer, uint32(len(msgBuf)))
	copy(buffer[4:], msgBuf)
	if err := writeAll(stream, buffer); err != nil {
		return fmt.Errorf("send message write buffer failed: %w", err)
	}
	return nil
}

func recvMessage(stream io.Reader, msg any) error {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return fmt.Errorf("recv message read length failed: %w", err)
	}
	msgBuf := make([]byte, binary.BigEndian.Uint32(lenBuf))
	if _, err := io.ReadFull(stream, msgBuf); err != nil {
		return fmt.Errorf("recv message read buffer failed: %w", err)
	}
	if err := json.Unmarshal(msgBuf, msg); err != nil {
		if enableDebugLogging {
			debug("failed to unmarshal message: %s", strconv.QuoteToASCII(string(msgBuf)))
		}
		return fmt.Errorf("recv message unmarshal failed: %w", err)
	}
	return nil
}

func sendCommandAndMessage(stream io.Writer, command string, msg any) error {
	if len(command) == 0 {
		return fmt.Errorf("send command is empty")
	}
	if len(command) > 255 {
		return fmt.Errorf("send command too long: %s", command)
	}

	msgBuf, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("send message marshal failed: %w", err)
	}

	totalLen := 1 + len(command) + 4 + len(msgBuf)
	buffer := make([]byte, totalLen)

	buffer[0] = uint8(len(command))
	copy(buffer[1:], []byte(command))

	binary.BigEndian.PutUint32(buffer[1+len(command):], uint32(len(msgBuf)))
	copy(buffer[1+len(command)+4:], msgBuf)

	if err := writeAll(stream, buffer); err != nil {
		return fmt.Errorf("send command and message failed: %w", err)
	}
	return nil
}

func sendError(stream Stream, err error) {
	if e := sendMessage(stream, errorMessage{Msg: err.Error()}); e != nil {
		warning("send error [%v] failed: %v", err, e)
	}
}

func sendErrorCode(stream Stream, code ErrCode, msg string) {
	if e := sendMessage(stream, errorMessage{code, msg}); e != nil {
		warning("send error [%d][%v] failed: %v", code, msg, e)
	}
}

func sendSuccess(stream Stream) error {
	return sendMessage(stream, errorMessage{Msg: kNoErrorMsg})
}

func recvError(stream Stream) error {
	var errMsg errorMessage
	if err := recvMessage(stream, &errMsg); err != nil {
		return fmt.Errorf("recv error failed: %w", err)
	}
	if errMsg.Msg != kNoErrorMsg {
		return &Error{errMsg.Code, errMsg.Msg}
	}
	return nil
}

func sendResponse(stream Stream, resp errorResponder) error {
	resp.getErrorMessage().Msg = kNoErrorMsg
	return sendMessage(stream, resp)
}

func recvResponse(stream Stream, resp errorResponder) error {
	if err := recvMessage(stream, resp); err != nil {
		return fmt.Errorf("recv response failed: %w", err)
	}
	if errMsg := resp.getErrorMessage(); errMsg.Msg != kNoErrorMsg {
		return &Error{errMsg.Code, errMsg.Msg}
	}
	return nil
}

type protocolClient interface {
	reset()
	closeClient() error
	getUdpForwarder() *udpForwarder
	newStream(connectTimeout time.Duration) (Stream, error)
	stats(s *TransportStats)
}

type kcpClient struct {
	conn      *kcp.UDPSession
	session   *smux.Session
	forwarder *udpForwarder
}

func (c *kcpClient) reset() {
	c.conn.ResetRTO()
}

func (c *kcpClient) closeClient() error {
	c.forwarder.Close()
	return c.session.Close()
}

func (c *kcpClient) getUdpForwarder() *udpForwarder {
	return c.forwarder
}

func (c *kcpClient) newStream(connectTimeout time.Duration) (Stream, error) {
	stream, err := c.session.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("kcp smux open stream failed: %w", err)
	}
	return &smuxStream{stream}, nil
}

type quicClient struct {
	conn      *quic.Conn
	forwarder *udpForwarder
}

func (c *quicClient) reset() {
	c.conn.ResetPTO()
}

func (c *quicClient) closeClient() error {
	c.forwarder.Close()
	return c.conn.CloseWithError(0, "")
}

func (c *quicClient) getUdpForwarder() *udpForwarder {
	return c.forwarder
}

func (c *quicClient) newStream(connectTimeout time.Duration) (Stream, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("quic open stream sync failed: %w", err)
	}
	return &quicStream{stream, c.conn}, err
}

func newProtoClient(opts *UdpClientOptions, client *SshUdpClient) (protocolClient, error) {
	switch opts.ServerInfo.Mode {
	case "":
		return nil, fmt.Errorf("%s", "Please upgrade tsshd")
	case kUdpModeKCP:
		return newKcpClient(opts, client, client.clientProxy, client.clientProxy.remoteAddr)
	case kUdpModeQUIC:
		return newQuicClient(opts, client.clientProxy, client.clientProxy.remoteAddr)
	default:
		return nil, fmt.Errorf("unknown tsshd mode: %s", opts.ServerInfo.Mode)
	}
}

func newKcpClient(opts *UdpClientOptions, client *SshUdpClient, udpConn net.PacketConn, remoteAddr net.Addr) (*kcpClient, error) {
	pass, err := hex.DecodeString(opts.ServerInfo.Pass)
	if err != nil {
		return nil, fmt.Errorf("decode pass [%s] failed: %w", opts.ServerInfo.Pass, err)
	}
	salt, err := hex.DecodeString(opts.ServerInfo.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt [%s] failed: %w", opts.ServerInfo.Pass, err)
	}

	crypto, err := newRotatingCrypto(client, pass, salt, kRekeyBytesThreshold, kRekeyTimeThreshold, false)
	if err != nil {
		return nil, fmt.Errorf("new rotating crypto failed: %w", err)
	}
	if client != nil {
		client.clientProxy.kcpCrypto = crypto
	}
	block := kcp.NewAEADCrypt(crypto)

	conn, err := kcp.NewConn2(remoteAddr, block, 1, 1, udpConn)
	if err != nil {
		return nil, fmt.Errorf("kcp new conn [%v] failed: %w", remoteAddr.String(), err)
	}
	conn.SetWindowSize(1024, 1024)
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetWriteDelay(false)

	if opts.ServerInfo.MTU != 0 {
		conn.SetMtu(int(opts.ServerInfo.MTU))
	} else if opts.ProxyClient != nil {
		conn.SetMtu(int(opts.ProxyClient.GetMaxDatagramSize()))
	} else {
		conn.SetMtu(kDefaultMTU)
	}

	session, err := smux.Client(conn, &smuxConfig)
	if err != nil {
		return nil, fmt.Errorf("kcp smux client failed: %w", err)
	}
	return &kcpClient{conn, session, &udpForwarder{conn: newKcpDatagramConn(conn)}}, nil
}

func newQuicClient(opts *UdpClientOptions, udpConn net.PacketConn, remoteAddr net.Addr) (*quicClient, error) {
	serverCert, err := hex.DecodeString(opts.ServerInfo.ServerCert)
	if err != nil {
		return nil, fmt.Errorf("decode server cert [%s] failed: %w", opts.ServerInfo.ServerCert, err)
	}
	clientCert, err := hex.DecodeString(opts.ServerInfo.ClientCert)
	if err != nil {
		return nil, fmt.Errorf("decode client cert [%s] failed: %w", opts.ServerInfo.ClientCert, err)
	}
	clientKey, err := hex.DecodeString(opts.ServerInfo.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("decode client key [%s] failed: %w", opts.ServerInfo.ClientKey, err)
	}

	clientTlsCert, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, fmt.Errorf("x509 key pair failed: %w", err)
	}
	serverCertPool := x509.NewCertPool()
	serverCertPool.AppendCertsFromPEM(serverCert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientTlsCert},
		RootCAs:      serverCertPool,
		ServerName:   "tsshd",
	}

	config := quicConfig
	if opts.ServerInfo.MTU != 0 {
		config.InitialPacketSize = opts.ServerInfo.MTU
		config.DisablePathMTUDiscovery = true
	} else if opts.ProxyClient != nil {
		config.InitialPacketSize = opts.ProxyClient.GetMaxDatagramSize()
		config.DisablePathMTUDiscovery = true
	} else {
		config.InitialPacketSize = kDefaultMTU
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.ConnectTimeout)
	defer cancel()
	conn, err := quic.Dial(ctx, udpConn, remoteAddr, tlsConfig, &config)
	if err != nil {
		return nil, fmt.Errorf("quic dail [%v] failed: %w", remoteAddr.String(), err)
	}
	return &quicClient{conn, &udpForwarder{conn: newQuicDatagramConn(conn, config.InitialPacketSize)}}, nil
}
