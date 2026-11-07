module github.com/bonjoski/fabrial

go 1.27.3

require (
	github.com/bonjoski/airlock v0.10.1
	github.com/bonjoski/stoneward v0.1.0
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/bonjoski/stoneward => ../stoneward

require (
	github.com/bonjoski/shield v0.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
)
