
.PHONY: test
test:
	@go test -v -coverprofile=profile.tmp ./... -coverpkg=./...
