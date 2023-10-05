#!/bin/bash

set -eu

SCRIPT_DIR=$(dirname "$0")
cd $SCRIPT_DIR

function randomHEX() {
  xxd -l $@ -p /dev/urandom
}

function randomASCII() {
  cat /dev/urandom | LC_ALL=C tr -dc 'a-zA-Z0-9' | fold -w $@ | head -n 1
}

function ASCIItoHEX() {
  echo -n "$@" | xxd -p | tr -d '\n'
}

if [[ -z ${COUNT:-} || $COUNT == 0 ]]; then
  echo "Invalid or missing COUNT"
  exit 1
fi

IDS=()
PORTS=()
SIGNING_KEYS=()
TENANT_NAMES=()

echo "Starting $COUNT realms..."

# Run jb-sw-realm COUNT times
for ((i = 0; i < COUNT; i++)); do
  IDS+=($(randomHEX 16))
  PORTS+=($((10000 + i)))
  TENANT_NAMES+=($(randomASCII 16))
  SIGNING_KEY_ASCII=$(randomASCII 32)
  SIGNING_KEYS+=($(ASCIItoHEX ${SIGNING_KEY_ASCII}))

  echo "Starting Realm $i (${IDS[$i]})..."

  TENANT_SECRETS='{"'${TENANT_NAMES[$i]}'":{"1":"'${SIGNING_KEY_ASCII}'"}}' \
  jb-sw-realm -port ${PORTS[$i]} -id "${IDS[$i]}" > /dev/null 2>&1 &

  echo "Started Realm $i!"
done

jobs -p > pids

echo "Started $COUNT realms."

# Generate the CONFIGURATION
CONFIGURATION='{"realms":['
for ((i = 0; i < COUNT; i++)); do
  CONFIGURATION+='{"id":"'${IDS[$i]}'","address":"http://localhost:'${PORTS[$i]}'"}'
  if ((i != COUNT - 1)); then
    CONFIGURATION+=','
  fi
done
CONFIGURATION+='],"register_threshold":'$COUNT',"recover_threshold":'$COUNT',"pin_hashing_mode":"FastInsecure"}'

echo "CONFIGURATION='$CONFIGURATION'" > outputs

# Generate the AUTH_TOKENS
AUTH_TOKENS='{'
for ((i = 0; i < COUNT; i++)); do
  echo "Creating token for Realm $i..."
  TOKEN=$(../../../target/debug/tokens create test ${TENANT_NAMES[$i]} ${IDS[$i]} ${SIGNING_KEYS[$i]} 1 HS256)
  echo "Created token for Realm $i!"

  AUTH_TOKENS+='"'${IDS[$i]}'":"'${TOKEN}'"'
  if ((i != COUNT - 1)); then
    AUTH_TOKENS+=','
  fi
done
AUTH_TOKENS+='}'

echo "AUTH_TOKENS='$AUTH_TOKENS'" >> outputs
