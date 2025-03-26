#!/bin/bash
set -e

# Official trusted BLAKE2b-512 checksum for powersOfTau28_hez_final_17.ptau
OFFICIAL_CHECKSUM="6247a3433948b35fbfae414fa5a9355bfb45f56efa7ab4929e669264a0258976741dfbe3288bfb49828e5df02c2e633df38d2245e30162ae7e3bcca5b8b49345"

echo "Downloading official ptau file..."
curl -o pot/pot_final.ptau https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_17.ptau

echo -e "\nVerifying BLAKE2b-512 checksum..."
DOWNLOADED_CHECKSUM=$(b2sum -l 512 pot/pot_final.ptau | awk '{print $1}')

if [ "$DOWNLOADED_CHECKSUM" != "$OFFICIAL_CHECKSUM" ]; then
    echo -e "\n\033[31mDANGER: Checksum verification failed!\033[0m"
    echo "Expected: $OFFICIAL_CHECKSUM"
    echo "Got:      $DOWNLOADED_CHECKSUM"
    echo "The file may be corrupted or malicious. Delete it immediately."
    rm -f pot/pot_final.ptau
    exit 1
else
    echo -e "\033[32mChecksum verified successfully!\033[0m"
fi
