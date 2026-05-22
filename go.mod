module github.com/bepass-org/psiphon

go 1.25.5

replace github.com/Psiphon-Labs/psiphon-tunnel-core => ./local_replacements/psiphon-tunnel-core

replace github.com/Psiphon-Labs/quic-go => ./local_replacements/quic-go

replace github.com/Psiphon-Labs/psiphon-tls => ./local_replacements/psiphon-tls

require (
	github.com/MakeNowJust/heredoc/v2 v2.0.1
	github.com/Psiphon-Labs/psiphon-tunnel-core v2.0.28+incompatible
	github.com/bepass-org/ipscanner v0.0.0-20240222153143-97adabc6ad92
	github.com/bepass-org/proxy v0.0.0-20240201095508-c86216dd0aea
	github.com/refraction-networking/conjure v0.9.1
	github.com/refraction-networking/utls v1.8.2
	golang.org/x/crypto v0.51.0
	golang.org/x/net v0.54.0
	golang.org/x/sys v0.44.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	gopkg.in/ini.v1 v1.67.2
	gvisor.dev/gvisor v0.0.0-20260517053402-77dbc433352e
)

require (
	filippo.io/bigmod v0.0.3 // indirect
	filippo.io/keygen v0.0.0-20240718133620-7f162efbbd87 // indirect
	github.com/AndreasBriese/bbloom v0.0.0-20170702084017-28f7e881ca57 // indirect
	github.com/Psiphon-Labs/bolt v0.0.0-20200624191537-23cedaef7ad7 // indirect
	github.com/Psiphon-Labs/goptlib v0.0.0-20200406165125-c0e32a7a3464 // indirect
	github.com/Psiphon-Labs/psiphon-tls v0.0.0-20250318183125-2a2fae2db378 // indirect
	github.com/Psiphon-Labs/quic-go v0.0.0-20230626192210-73f29effc9da // indirect
	github.com/Psiphon-Labs/tls-tris v0.0.0-20230824155421-58bf6d336a9a // indirect
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/armon/go-proxyproto v0.0.0-20180202201750-5b7edb60ff5f // indirect
	github.com/bifurcation/mint v0.0.0-20180306135233-198357931e61 // indirect
	github.com/cheekybits/genny v0.0.0-20170328200008-9127e812e1e9 // indirect
	github.com/cognusion/go-cache-lru v0.0.0-20170419142635-f73e2280ecea // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/dgraph-io/badger v1.5.4-0.20180815194500-3a87f6d9c273 // indirect
	github.com/dgryski/go-farm v0.0.0-20180109070241-2de33835d102 // indirect
	github.com/flynn/noise v1.1.0 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/pprof v0.0.0-20211214055906-6f57359322fd // indirect
	github.com/grafov/m3u8 v0.0.0-20171211212457-6ab8f28ed427 // indirect
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/libp2p/go-reuseport v0.4.0 // indirect
	github.com/miekg/dns v1.1.62 // indirect
	github.com/mroth/weightedrand v1.0.0 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pion/dtls/v2 v2.2.12 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/sctp v1.8.35 // indirect
	github.com/pion/stun v0.6.1 // indirect
	github.com/pion/transport/v2 v2.2.10 // indirect
	github.com/pion/transport/v3 v3.0.7 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/quic-go/qtls-go1-20 v0.4.1 // indirect
	github.com/quic-go/quic-go v0.40.1 // indirect
	github.com/refraction-networking/ed25519 v0.1.2 // indirect
	github.com/refraction-networking/gotapdance v1.7.10 // indirect
	github.com/refraction-networking/obfs4 v0.1.2 // indirect
	github.com/sergeyfrolov/bsbuffer v0.0.0-20180903213811-94e85abb8507 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/syndtr/gocapability v0.0.0-20170704070218-db04d3cc01c8 // indirect
	github.com/wader/filtertransport v0.0.0-20200316221534-bdd9e61eee78 // indirect
	github.com/wlynxg/anet v0.0.3 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.6.0 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2 v2.10.1 // indirect
	go.uber.org/mock v0.3.0 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.44.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
