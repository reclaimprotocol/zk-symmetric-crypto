if [ -z "${ALG}" ]; then
	echo "\$ALG is not set. Please set to chacha20, aes-128-ctr or aes-256-ctr"
  exit 1
fi

set ALG = $ALG

set -e
echo "building circuit..."
circom circuits/$ALG/circuit.circom --r1cs --wasm --O2 --inspect -o resources/$ALG/
mv resources/$ALG/circuit_js/circuit.wasm resources/$ALG/circuit.wasm
rm -rf resources/$ALG/circuit_js
echo "generating verification key..."
npm exec snarkjs -- groth16 setup resources/$ALG/circuit.r1cs pot/pot_final.ptau resources/$ALG/circuit_0000.zkey
npm exec snarkjs -- zkey contribute resources/$ALG/circuit_0000.zkey resources/$ALG/circuit_0001.zkey --name="1st Contributor" -v -e=$(openssl rand -hex 10240)
npm exec snarkjs -- zkey beacon resources/$ALG/circuit_0001.zkey resources/$ALG/circuit_final.zkey $(openssl rand -hex 128) 20
rm -rf resources/$ALG/circuit_0000.zkey
rm -rf resources/$ALG/circuit_0001.zkey
rm -rf resources/$ALG/circuit_0002.zkey
