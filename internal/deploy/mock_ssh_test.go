package deploy_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type mockSSHExecFunc func(cmd string, stdin []byte) (stdout, stderr string, exitCode int)

type mockSSHServer struct {
	t        *testing.T
	listener net.Listener
	addr     string
	port     int

	mu                 sync.Mutex
	hostSigner         ssh.Signer
	hostFP             string
	allowedPubKey      ssh.PublicKey
	allowedPassword    string
	disablePosixRename bool
	execHandler        mockSSHExecFunc
	executedCmds       []string
	inMemSFTP          sftp.Handlers
	connCount          int

	wg     sync.WaitGroup
	closed bool
}

func newMockSSHServer(t *testing.T, allowedPub ssh.PublicKey, allowedPass string) *mockSSHServer {
	t.Helper()
	signer, fp := generateSSHHostKey(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock ssh: %v", err)
	}
	tcpAddr := ln.Addr().(*net.TCPAddr)

	s := &mockSSHServer{
		t:               t,
		listener:        ln,
		addr:            "127.0.0.1",
		port:            tcpAddr.Port,
		hostSigner:      signer,
		hostFP:          fp,
		allowedPubKey:   allowedPub,
		allowedPassword: allowedPass,
		inMemSFTP:       sftp.InMemHandler(),
	}

	s.wg.Add(1)
	go s.serve()

	t.Cleanup(func() {
		s.Close()
	})
	return s
}

func (s *mockSSHServer) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	_ = s.listener.Close()
	s.wg.Wait()
}

func (s *mockSSHServer) RotateHostKey() string {
	signer, fp := generateSSHHostKey(s.t)
	s.mu.Lock()
	s.hostSigner = signer
	s.hostFP = fp
	s.mu.Unlock()
	return fp
}

func (s *mockSSHServer) HostFingerprint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hostFP
}

func (s *mockSSHServer) SetDisablePosixRename(disable bool) {
	s.mu.Lock()
	s.disablePosixRename = disable
	s.mu.Unlock()
}

func (s *mockSSHServer) SetExecHandler(fn mockSSHExecFunc) {
	s.mu.Lock()
	s.execHandler = fn
	s.mu.Unlock()
}

func (s *mockSSHServer) ExecutedCommands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.executedCmds))
	copy(out, s.executedCmds)
	return out
}

func (s *mockSSHServer) ConnCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connCount
}

func (s *mockSSHServer) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConn(c)
		}(conn)
	}
}

func (s *mockSSHServer) handleConn(rawConn net.Conn) {
	defer rawConn.Close()

	s.mu.Lock()
	s.connCount++
	signer := s.hostSigner
	allowedPub := s.allowedPubKey
	allowedPass := s.allowedPassword
	s.mu.Unlock()

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if allowedPub != nil && bytes.Equal(key.Marshal(), allowedPub.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("public key rejected")
		},
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if allowedPass != "" && string(pass) == allowedPass {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("password rejected")
		},
	}
	cfg.AddHostKey(signer)

	sshConn, chans, reqs, err := ssh.NewServerConn(rawConn, cfg)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChan.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(channel, requests)
	}
}

func (s *mockSSHServer) handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "subsystem":
			if len(req.Payload) >= 4 {
				subLen := binary.BigEndian.Uint32(req.Payload[:4])
				if int(subLen)+4 <= len(req.Payload) && string(req.Payload[4:4+subLen]) == "sftp" {
					_ = req.Reply(true, nil)
					s.serveSFTP(channel)
					return
				}
			}
			_ = req.Reply(false, nil)

		case "exec":
			if len(req.Payload) < 4 {
				_ = req.Reply(false, nil)
				return
			}
			cmdLen := binary.BigEndian.Uint32(req.Payload[:4])
			if int(cmdLen)+4 > len(req.Payload) {
				_ = req.Reply(false, nil)
				return
			}
			cmd := string(req.Payload[4 : 4+cmdLen])
			_ = req.Reply(true, nil)

			stdinBytes, _ := io.ReadAll(channel)

			s.mu.Lock()
			s.executedCmds = append(s.executedCmds, cmd)
			fn := s.execHandler
			s.mu.Unlock()

			stdout, stderr, exitCode := "", "", 0
			if fn != nil {
				stdout, stderr, exitCode = fn(cmd, stdinBytes)
			}
			if stdout != "" {
				_, _ = io.WriteString(channel, stdout)
			}
			if stderr != "" {
				_, _ = io.WriteString(channel.Stderr(), stderr)
			}
			var statusPayload [4]byte
			binary.BigEndian.PutUint32(statusPayload[:], uint32(exitCode))
			_, _ = channel.SendRequest("exit-status", false, statusPayload[:])
			return

		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (s *mockSSHServer) serveSFTP(channel ssh.Channel) {
	s.mu.Lock()
	disablePosix := s.disablePosixRename
	handlers := s.inMemSFTP
	s.mu.Unlock()

	if disablePosix {
		wrapped := sftp.Handlers{
			FileGet:  handlers.FileGet,
			FilePut:  handlers.FilePut,
			FileCmd:  noPosixRenameFileCmder{inner: handlers.FileCmd},
			FileList: handlers.FileList,
		}
		srv := sftp.NewRequestServer(channel, wrapped)
		_ = srv.Serve()
		_ = srv.Close()
		return
	}

	srv, err := sftp.NewServer(channel)
	if err != nil {
		return
	}
	_ = srv.Serve()
	_ = srv.Close()
}

type noPosixRenameFileCmder struct {
	inner sftp.FileCmder
}

func (n noPosixRenameFileCmder) Filecmd(r *sftp.Request) error {
	return n.inner.Filecmd(r)
}

func (n noPosixRenameFileCmder) PosixRename(r *sftp.Request) error {
	return sftp.ErrSSHFxOpUnsupported
}

func generateSSHHostKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("ssh signer from key: %v", err)
	}
	return signer, ssh.FingerprintSHA256(signer.PublicKey())
}

func generateClientSSHKeyPair(t *testing.T, passphrase string) (privPEM string, pub ssh.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client ecdsa key: %v", err)
	}
	var block *pem.Block
	if passphrase != "" {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	} else {
		block, err = ssh.MarshalPrivateKey(priv, "")
	}
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	pubKey, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return string(pem.EncodeToMemory(block)), pubKey
}
