module github.com/chainreactors/fingers/re2

go 1.24.0

require (
	github.com/chainreactors/fingers v1.2.2-0.20260925174709-350638e91234
	github.com/wasilibs/go-re2 v1.6.0
)

require (
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible // indirect
	github.com/chainreactors/logs v0.0.0-20260508055944-c678762ed15c // indirect
	github.com/chainreactors/neutron v0.1.1-0.20260714062907-716c6b167cb6 // indirect
	github.com/chainreactors/utils v0.0.0-20260629043228-93bdd2142c9a // indirect
	github.com/chainreactors/utils/parsers v0.0.4-0.20260925164932-39c659c84c64 // indirect
	github.com/chainreactors/words v0.0.0-20260520145736-270600e60fb4 // indirect
	github.com/dlclark/regexp2 v1.11.5 // indirect
	github.com/facebookincubator/nvdtools v0.1.5 // indirect
	github.com/go-dedup/megophone v0.0.0-20170830025436-f01be21026f5 // indirect
	github.com/go-dedup/simhash v0.0.0-20170904020510-9ecaca7b509c // indirect
	github.com/go-dedup/text v0.0.0-20170907015346-8bb1b95e3cb7 // indirect
	github.com/hashicorp/go-version v1.6.0 // indirect
	github.com/mozillazg/go-pinyin v0.20.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/tetratelabs/wazero v1.11.0 // indirect
	github.com/twmb/murmur3 v1.1.8 // indirect
	github.com/wasilibs/wazero-helpers v0.0.0-20250123031827-cd30c44769bb // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/wasilibs/go-re2 => github.com/chainreactors/go-re2 v1.11.1-0.20260716152604-8121b6cd261e

// Development and CI use the checkout; downstream builds use the version
// required above.
replace github.com/chainreactors/fingers => ../
