set -e
npm exec snarkjs -- powersoftau new bls12-381 18 pot18_0000.ptau
npm exec snarkjs -- powersoftau contribute pot18_0000.ptau pot18_0001.ptau --name="First contribution" -e=$(openssl rand -hex 10240)
npm exec snarkjs -- powersoftau contribute pot18_0001.ptau pot18_0002.ptau --name="Second contribution" -e=$(openssl rand -hex 10240)
npm exec snarkjs -- powersoftau contribute pot18_0002.ptau pot18_0003.ptau --name="Third contribution" -e=$(openssl rand -hex 10240)
#npm exec snarkjs -- powersoftau verify pot18_0003.ptau
npm exec snarkjs -- powersoftau beacon pot18_0003.ptau pot18_beacon.ptau $(openssl rand -hex 128) 20 -n="Final Beacon"
#npm exec snarkjs -- powersoftau beacon pot18_0003.ptau pot18_beacon.ptau $(curl https://drand.cloudflare.com/public/latest | jq -r ".randomness") 20 -n="Final Beacon"
npm exec snarkjs -- powersoftau prepare phase2 pot18_beacon.ptau pot18_final.ptau
#npm exec snarkjs -- powersoftau verify pot18_final.ptau

rm pot18_0000.ptau
rm pot18_0001.ptau
rm pot18_0002.ptau
rm pot18_0003.ptau
rm pot18_beacon.ptau
mv pot18_final.ptau pot/pot18_final.ptau

