#!/bin/bash
set -e

# Official trusted checksum for powersOfTau28_hez_final_17.ptau
# (Replace with the actual published checksum from Hermez/Polygon)
OFFICIAL_CHECKSUM="add your checksum"  # EXAMPLE - GET REAL VALUE!

echo "Downloading official ptau file..."
curl -o pot/pot_final.ptau https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_17.ptau

echo -e "\nVerifying checksum..."
DOWNLOADED_CHECKSUM=$(sha256sum pot/pot_final.ptau | awk '{print $1}')

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
