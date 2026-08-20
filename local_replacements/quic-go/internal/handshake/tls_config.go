package handshake

import (
	"net"

	ptls "github.com/Psiphon-Labs/psiphon-tls"
)

func setupConfigForServer(conf *ptls.Config, localAddr, remoteAddr net.Addr) *ptls.Config {
	// Workaround for https://github.com/golang/go/issues/60506.
	// This initializes the session tickets _before_ cloning the config.
	_, _ = conf.DecryptTicket(nil, ptls.ConnectionState{})

	conf = conf.Clone()
	conf.MinVersion = ptls.VersionTLS13

	// The tls.Config contains two callbacks that pass in a tls.ClientHelloInfo.
	// Since crypto/tls doesn't do it, we need to make sure to set the Conn field with a fake net.Conn
	// that allows the caller to get the local and the remote address.
	if conf.GetConfigForClient != nil {
		gcfc := conf.GetConfigForClient
		conf.GetConfigForClient = func(info *ptls.ClientHelloInfo) (*ptls.Config, error) {
			info.Conn = &conn{localAddr: localAddr, remoteAddr: remoteAddr}
			c, err := gcfc(info)
			if c != nil {
				c = setupConfigForServer(c, localAddr, remoteAddr)
			}
			return c, err
		}
	}
	if conf.GetCertificate != nil {
		gc := conf.GetCertificate
		conf.GetCertificate = func(info *ptls.ClientHelloInfo) (*ptls.Certificate, error) {
			info.Conn = &conn{localAddr: localAddr, remoteAddr: remoteAddr}
			return gc(info)
		}
	}
	return conf
}
