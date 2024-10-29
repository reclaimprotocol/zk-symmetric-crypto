if [ -z "${ALG}" ]; then
	echo "\$ALG is not set. Please set to chacha20, aes-128-ctr or aes-256-ctr"
  exit 1
fi

OUT_DIR="../resources/snarkjs/$ALG"

set -e

echo "building $ALG circuit..."
circom circuits/$ALG/circuit.circom --r1cs --wasm --O2 --inspect -o $OUT_DIR
mv $OUT_DIR/circuit_js/circuit.wasm $OUT_DIR/circuit.wasm
rm -rf $OUT_DIR/circuit_js

echo "generating verification key..."
npm exec snarkjs -- groth16 setup $OUT_DIR/circuit.r1cs pot/pot_final.ptau $OUT_DIR/circuit_0000.zkey
npm exec snarkjs -- zkey contribute $OUT_DIR/circuit_0000.zkey $OUT_DIR/circuit_0001.zkey --name="1st Contributor" -v -e=$(openssl rand -hex 10240)
npm exec snarkjs -- zkey beacon $OUT_DIR/circuit_0001.zkey $OUT_DIR/circuit_final.zkey $(openssl rand -hex 128) 20
rm -rf $OUT_DIR/circuit_0000.zkey
rm -rf $OUT_DIR/circuit_0001.zkey
rm -rf $OUT_DIR/circuit_0002.zkey
