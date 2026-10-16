module github.com/bonjoski/fabrial

go 1.27.1

replace (
	bonjoski/argus => /Users/benskolmoski/supplychain/argus
	github.com/bonjoski/airlock => /Users/benskolmoski/supplychain/airlock
	github.com/bonjoski/locksmith/v2 => /Users/benskolmoski/code/locksmith
)

require github.com/bonjoski/airlock v0.0.0-00010101000000-000000000000

require gopkg.in/yaml.v3 v3.0.1 // indirect
