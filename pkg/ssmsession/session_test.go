package ssmsession_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"golang.org/x/crypto/ssh"

	"github.com/wrouesnel/ssm-proxycommand/internal/fakeaws"
	"github.com/wrouesnel/ssm-proxycommand/pkg/ssmsession"
)

// echoServer is the stand-in for a TCP service on the instance.
func echoServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().String()
}

func startAgent(t *testing.T, a *fakeaws.Agent) {
	a.Start()
	t.Cleanup(func() {
		a.Close()
		for _, e := range a.Errors() {
			t.Errorf("fake agent: %s", e)
		}
	})
}

func testOptions(t *testing.T, a *fakeaws.Agent) ssmsession.Options {
	return ssmsession.Options{
		SessionID:  "sess-1",
		StreamURL:  a.URL(),
		TokenValue: fakeaws.InitialToken,
		TargetID:   "i-0123456789abcdef0",
		Resume:     a.Resume,
	}
}

// startSession runs a session over pipes and returns the client's input writer, output reader
// and a channel that receives Run's result.
func startSession(t *testing.T, opts ssmsession.Options) (io.WriteCloser, io.Reader, <-chan error) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		err := ssmsession.Run(ctx, opts, inR, outW)
		outW.CloseWithError(io.EOF)
		done <- err
	}()
	return inW, outR, done
}

// echoTransfer pushes size random bytes through an echo target and checks they all come back.
func echoTransfer(t *testing.T, a *fakeaws.Agent, opts ssmsession.Options, size int) {
	t.Helper()
	in, out, done := startSession(t, opts)

	data := make([]byte, size)
	_, _ = rand.Read(data)
	go func() {
		// Write in uneven pieces to exercise chunking.
		for off := 0; off < len(data); {
			n := min(len(data)-off, 777+off%5000)
			if _, err := in.Write(data[off : off+n]); err != nil {
				return
			}
			off += n
		}
	}()

	got := make([]byte, size)
	if _, err := io.ReadFull(out, got); err != nil {
		t.Fatalf("reading echoed data: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("echoed data does not match")
	}
	in.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("session did not end after input closed")
	}
	if !a.Terminated() {
		t.Error("client did not send the TerminateSession flag")
	}
}

func TestEchoSession(t *testing.T) {
	a := fakeaws.NewAgent(echoServer(t))
	startAgent(t, a)
	echoTransfer(t, a, testOptions(t, a), 1<<20)
}

func TestLossyChannel(t *testing.T) {
	a := fakeaws.NewAgent(echoServer(t))
	a.DropInput = 0.05
	a.DropOutput = 0.05
	a.DupOutput = 0.05
	startAgent(t, a)
	echoTransfer(t, a, testOptions(t, a), 256<<10)
}

func TestEncryptedSession(t *testing.T) {
	a := fakeaws.NewAgent(echoServer(t))
	a.DataKey = make([]byte, 64)
	_, _ = rand.Read(a.DataKey)
	startAgent(t, a)
	opts := testOptions(t, a)
	opts.KMS = &fakeaws.KMS{Key: a.DataKey, Check: func(in *kms.GenerateDataKeyInput) error {
		if *in.NumberOfBytes != 64 || in.EncryptionContext["aws:ssm:SessionId"] != "sess-1" || in.EncryptionContext["aws:ssm:TargetId"] != "i-0123456789abcdef0" {
			t.Errorf("unexpected GenerateDataKey input: %+v", in)
		}
		return nil
	}}
	echoTransfer(t, a, opts, 256<<10)
}

func TestEncryptedSessionWithoutKMSFails(t *testing.T) {
	a := fakeaws.NewAgent(echoServer(t))
	a.DataKey = make([]byte, 64)
	startAgent(t, a)
	_, _, done := startSession(t, testOptions(t, a))
	err := <-done
	if err == nil || !strings.Contains(err.Error(), "KMS") {
		t.Fatalf("Run = %v, want KMS error", err)
	}
}

func TestResumeAfterConnectionLoss(t *testing.T) {
	a := fakeaws.NewAgent(echoServer(t))
	a.KillAfter = 200
	startAgent(t, a)
	echoTransfer(t, a, testOptions(t, a), 1<<20)
	if n := a.Connections(); n < 2 {
		t.Fatalf("expected a reconnection, saw %d connection(s)", n)
	}
}

func TestConnectionLossWithoutResumeFails(t *testing.T) {
	a := fakeaws.NewAgent(echoServer(t))
	a.KillAfter = 50
	startAgent(t, a)
	opts := testOptions(t, a)
	opts.Resume = nil
	in, out, done := startSession(t, opts)
	go func() { _, _ = io.Copy(io.Discard, out) }()
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := in.Write(buf); err != nil {
				return
			}
		}
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "connection lost") {
			t.Fatalf("Run = %v, want connection lost", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("session did not fail")
	}
}

func TestUnsupportedSessionType(t *testing.T) {
	a := fakeaws.NewAgent(echoServer(t))
	a.SessionType = "Standard_Stream"
	startAgent(t, a)
	_, _, done := startSession(t, testOptions(t, a))
	err := <-done
	if err == nil || !strings.Contains(err.Error(), "unsupported session type") {
		t.Fatalf("Run = %v, want unsupported session type", err)
	}
}

func TestRemoteClose(t *testing.T) {
	// The target sends a banner and hangs up; the session must deliver it all and end cleanly.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	banner := bytes.Repeat([]byte("SSH-2.0-fake\r\n"), 5000)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write(banner)
		c.Close()
	}()
	a := fakeaws.NewAgent(l.Addr().String())
	startAgent(t, a)
	_, out, done := startSession(t, testOptions(t, a))
	got, err := io.ReadAll(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, banner) {
		t.Fatalf("received %d bytes, want %d", len(got), len(banner))
	}
	if err := <-done; err != nil {
		t.Fatalf("Run = %v", err)
	}
}

func TestContextCancel(t *testing.T) {
	a := fakeaws.NewAgent(echoServer(t))
	startAgent(t, a)
	inR, _ := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ssmsession.Run(ctx, testOptions(t, a), inR, io.Discard) }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run ignored cancellation")
	}
}

// TestSSHOverSession runs a real SSH handshake and command over the session, across a lossy
// channel that also drops its websocket mid-session.
func TestSSHOverSession(t *testing.T) {
	srv, err := fakeaws.StartSSHServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	addr := srv.Addr
	a := fakeaws.NewAgent(addr)
	a.DropInput = 0.02
	a.DropOutput = 0.02
	a.KillAfter = 30
	startAgent(t, a)

	in, out, done := startSession(t, testOptions(t, a))
	conn := &pipeConn{r: out, w: in}
	cc, chans, reqs, err := ssh.NewClientConn(conn, "i-0123456789abcdef0", &ssh.ClientConfig{
		User:            "tester",
		Auth:            []ssh.AuthMethod{ssh.Password("secret")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         20 * time.Second,
	})
	if err != nil {
		t.Fatalf("SSH handshake: %v", err)
	}
	client := ssh.NewClient(cc, chans, reqs)
	for i := 0; i < 3; i++ {
		sess, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		payload := strings.Repeat("x", 100000)
		sess.Stdin = strings.NewReader(payload)
		got, err := sess.Output("wc -c")
		if err != nil {
			t.Fatalf("command: %v", err)
		}
		if strings.TrimSpace(string(got)) != "100000" {
			t.Fatalf("command output = %q", got)
		}
	}
	client.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("session did not end")
	}
}

type pipeConn struct {
	r io.Reader
	w io.WriteCloser
	net.Conn
}

func (p *pipeConn) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeConn) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *pipeConn) Close() error                { return p.w.Close() }
func (p *pipeConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (p *pipeConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
