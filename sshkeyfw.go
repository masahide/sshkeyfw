package sshkeyfw

import (
	"io"
	"os"
	"path"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/xerrors"
)

type SSHKeyfw struct {
	Insecure   bool   `default:"true"`
	PrivateKey []byte `default:""`

	client       *ssh.Client
	agentSession *ssh.Session
}

func (s *SSHKeyfw) getHostKeyCallback(insecure bool) (ssh.HostKeyCallback, error) {
	if insecure {
		// nolint: gosec
		return ssh.InsecureIgnoreHostKey(), nil
	}
	file := path.Join(os.Getenv("HOME"), ".ssh/known_hosts")
	cb, err := knownhosts.New(file)
	if err != nil {
		return nil, xerrors.Errorf("knownhosts.New %w", err)
	}
	return cb, nil
}

// Connect  Generate ssh-agent using the specified private key, perform agent forward and connect to the specified host
func (s *SSHKeyfw) Connect(target, user string) error {
	hostKeyCB, err := s.getHostKeyCallback(s.Insecure)
	if err != nil {
		return err
	}
	signer, err := ssh.ParsePrivateKey(s.PrivateKey)
	if err != nil {
		return xerrors.Errorf("unable to ParsePrivateKey: %w", err)
	}
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCB,
	}
	s.client, err = ssh.Dial("tcp", target, config)
	if err != nil {
		return xerrors.Errorf("Failed to dial: %w", err)
	}
	//defer client.Close()
	s.agentSession, err = s.client.NewSession()
	if err != nil {
		return xerrors.Errorf("NewSession err: %w", err)
	}
	//defer agentSession.Close()
	key, err := ssh.ParseRawPrivateKey(s.PrivateKey)
	if err != nil {
		return xerrors.Errorf("unable to ParseRawPrivateKey key: %w", err)
	}
	keyAgent := agent.NewKeyring()
	if err = keyAgent.Add(agent.AddedKey{
		PrivateKey:       key,
		ConfirmBeforeUse: false,
		LifetimeSecs:     3600,
	}); err != nil {
		return xerrors.Errorf("keyAgent.Add err: %w", err)
	}
	if err = agent.ForwardToAgent(s.client, keyAgent); err != nil {
		return xerrors.Errorf("agetn.ForwardToAgent err: %w", err)
	}
	if err = agent.RequestAgentForwarding(s.agentSession); err != nil {
		return xerrors.Errorf("agetn.RequestAgentForwarding err: %w", err)
	}
	return nil
}

// Run command
func (s *SSHKeyfw) Run(cmd string, outW, errW io.Writer, inR io.Reader) error {
	sess, err := s.client.NewSession()
	if err != nil {
		return xerrors.Errorf("Failed to create ssh session: %w", err)
	}
	defer sess.Close()

	sess.Stdout = outW
	sess.Stderr = errW
	sess.Stdin = inR
	return sess.Run(cmd)
}

// Close connection
func (s *SSHKeyfw) Close() {
	if s.agentSession != nil {
		s.agentSession.Close()
		s.agentSession = nil
	}
	if s.client != nil {
		s.client.Close()
		s.client = nil
	}
}
