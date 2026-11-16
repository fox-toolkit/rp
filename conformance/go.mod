module conformance

go 1.26.0

replace (
	github.com/fox-toolkit/rp => ../
	github.com/fox-toolkit/rp/store/redis => ../store/redis
)

require (
	github.com/fox-toolkit/fox v1.1.1
	github.com/fox-toolkit/rp v0.8.2
	github.com/fox-toolkit/rp/store/redis v0.2.0
	github.com/redis/go-redis/v9 v9.23.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/coreos/go-oidc/v3 v3.21.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.9 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/oauth2 v0.38.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
)
