if [ -z "${GOARCH}" ]; then
	echo "\$GOARCH is not set. Please set to x86_64 or arm64"
  exit 1
fi

export GOOS="${GOOS:-linux}"
OUT_PREFIX="../bin/gnark/$GOOS-$GOARCH-"

set -e

build() {
	local module="$1"
	CGO_ENABLED=1 go build \
		-trimpath \
		-ldflags '-s -w' \
		-buildmode=c-shared \
		-o "$OUT_PREFIX-$module.so" \
		libraries/prover/$module.go
  	
	echo "Built $module"
}

build "libprove"
build "libverify"
