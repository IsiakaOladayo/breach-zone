#!/bin/sh
set -e
echo "Downloading Trufflehog v3 binary directly..."
curl -sSfL https://githubusercontent.com | sh -s -- -b .
if [ -f ./trufflehog ]; then
    echo "Binary downloaded successfully. Moving to secure system folder..."
    sudo mv ./trufflehog /usr/local/bin/trufflehog
    sudo chmod +x /usr/local/bin/trufflehog
    echo "Trufflehog v3 successfully installed!"
else
    echo "Direct download failed. Attempting alternative compiled package map..."
    curl -L -o tf.tar.gz https://github.com
    tar -xf tf.tar.gz trufflehog
    sudo mv trufflehog /usr/local/bin/trufflehog
    sudo chmod +x /usr/local/bin/trufflehog
    rm tf.tar.gz
    echo "Trufflehog v3 alternative installation successful!"
fi
rm -f install_trufflehog.sh
hash -r
