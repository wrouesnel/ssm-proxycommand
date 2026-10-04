package fakeaws

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
)

// SSHServer is a minimal SSH server standing in for sshd on the instance. It supports one exec
// command, "wc -c", which replies with the number of bytes read from stdin; any other command
// is echoed back.
type SSHServer struct {
	Addr string
	l    net.Listener
}

// StartSSHServer listens on localhost. Clients authenticate as user "tester" with either
// password "secret" or the given public key.
func StartSSHServer(authorized ssh.PublicKey) (*SSHServer, error) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "tester" && string(pass) == "secret" {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == "tester" && authorized != nil && string(key.Marshal()) == string(authorized.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	cfg.AddHostKey(signer)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &SSHServer{Addr: l.Addr().String(), l: l}
	go func() {
		for {
			nc, err := l.Accept()
			if err != nil {
				return
			}
			go serveSSH(nc, cfg)
		}
	}()
	return s, nil
}

// Close stops listening.
func (s *SSHServer) Close() { s.l.Close() }

func serveSSH(nc net.Conn, cfg *ssh.ServerConfig) {
	defer nc.Close()
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	var wg sync.WaitGroup
	for nch := range chans {
		if nch.ChannelType() != "session" {
			_ = nch.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, chReqs, err := nch.Accept()
		if err != nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer ch.Close()
			for req := range chReqs {
				if req.Type != "exec" {
					_ = req.Reply(req.Type == "env" || req.Type == "pty-req", nil)
					continue
				}
				var exec struct{ Command string }
				_ = ssh.Unmarshal(req.Payload, &exec)
				_ = req.Reply(true, nil)
				if exec.Command == "wc -c" {
					n, _ := io.Copy(io.Discard, ch)
					_, _ = io.WriteString(ch, strconv.FormatInt(n, 10)+"\n")
				} else {
					_, _ = io.WriteString(ch, exec.Command+"\n")
				}
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				return
			}
		}()
	}
	wg.Wait()
}
