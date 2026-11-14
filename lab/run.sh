#!/usr/bin/env bash
# End-to-end lab: build hunter, start a Rocky 9 container (sshd on
# 127.0.0.1 only), baseline it, plant the kit stand-ins, sweep again and
# show what hunter caught. Tears the container down at the end unless
# KEEP=1.
set -euo pipefail
cd "$(dirname "$0")"
LAB=$PWD
NAME=hunter-lab
PORT=${PORT:-2222}

../build.sh >/dev/null
[ -f .key ] || ssh-keygen -q -t ed25519 -N '' -f .key -C hunter-lab
docker build -q -t hunter-lab . >/dev/null
docker rm -f $NAME >/dev/null 2>&1 || true
docker run -d --name $NAME -p 127.0.0.1:$PORT:22 hunter-lab >/dev/null
trap '[ "${KEEP:-0}" = 1 ] || docker rm -f '$NAME' >/dev/null' EXIT
docker exec -i $NAME sh -c 'cat >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys' < .key.pub
sleep 1

H="../dist/hunter"
SSH=(-i "$LAB/.key" -o UserKnownHostsFile="$LAB/known_hosts" -o StrictHostKeyChecking=no)
RUNS="$LAB/runs"
rm -rf "$RUNS"

echo "== clean sweep (becomes the baseline)"
"$H" sweep "${SSH[@]}" -runs "$RUNS" -since 2m -max 0 "root@127.0.0.1:$PORT"

echo "== planting kit stand-ins"
docker exec -i $NAME bash -s < plant.sh

echo "== sweep after compromise"
# -since 2m keeps the image's own extraction time out of the timestomp window
"$H" sweep "${SSH[@]}" -runs "$RUNS" -since 2m -max 0 "root@127.0.0.1:$PORT"

echo "== inspect + quarantine through hunter remote"
"$H" remote "${SSH[@]}" "root@127.0.0.1:$PORT" inspect -strings 5 /usr/lib/openssh/ssh-keygen
"$H" remote "${SSH[@]}" --yes "root@127.0.0.1:$PORT" quarantine --kill /usr/sbin/rt-tagd
