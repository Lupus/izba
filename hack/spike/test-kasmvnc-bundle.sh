#!/usr/bin/env bash
# SPIKE (throwaway): prove the self-contained KasmVNC bundle runs inside
# dissimilar container images with NO help from the image — mirroring how
# izba-init would `crun exec` each process into the workload container with
# the bundle bind-mounted read-only at /opt/izba-vnc.
#
# Per image: start Xkasmvnc as the container entrypoint (direct ELF exec, no
# shell), exec openbox + xterm into it, then assert the KasmVNC web client
# answers over HTTP and a VNC screenshot round-trips.
set -euo pipefail

BUNDLE="${BUNDLE_OUT:?set BUNDLE_OUT to the built bundle dir}"
IMAGES=("debian:bookworm-slim" "alpine:3.22" "busybox:latest")
BASE_PORT=6910

ENV_ARGS=(
  -e XKB_BINDIR=/opt/izba-vnc/bin
  -e FONTCONFIG_PATH=/opt/izba-vnc/etc/fonts
  -e XDG_CONFIG_DIRS=/opt/izba-vnc/etc
  -e XDG_DATA_DIRS=/opt/izba-vnc/share
  -e HOME=/tmp
  -e DISPLAY=:1
)

XVNC_ARGS=(
  :1 -geometry 1280x800 -depth 24
  -websocketPort 6901 -interface 0.0.0.0
  -DisableBasicAuth -SecurityTypes None -sslOnly 0
  -httpd /opt/izba-vnc/share/kasmvnc/www
  -fp /opt/izba-vnc/share/fonts/X11/misc
  -xkbdir /opt/izba-vnc/share/xkb
  -ac -noreset
  -publicIP 127.0.0.1  # suppress the STUN-ish public-IP lookup (egress!)
)

pass=0 fail=0
for i in "${!IMAGES[@]}"; do
  img="${IMAGES[$i]}"
  port=$((BASE_PORT + i))
  name="kvspike-$i"
  echo "=== $img (host port $port) ==="
  docker rm -f "$name" >/dev/null 2>&1 || true
  # The xkbcomp bind mirrors what izba's generate_spec would author: the X
  # server shells out to a HARDCODED /usr/bin/xkbcomp (no env override), so
  # the bundle's patched xkbcomp is bound there. Requires /bin/sh in the
  # image (X server Popen) — a documented limitation.
  docker run -d --name "$name" --rm \
    -v "$BUNDLE:/opt/izba-vnc:ro" \
    -v "$BUNDLE/bin/xkbcomp:/usr/bin/xkbcomp:ro" \
    -p "127.0.0.1:$port:6901" \
    "${ENV_ARGS[@]}" \
    "$img" /opt/izba-vnc/bin/Xkasmvnc "${XVNC_ARGS[@]}" >/dev/null

  ok=1
  for _ in $(seq 1 20); do
    curl -fsS -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null && break
    sleep 0.5
    if ! docker ps -q --no-trunc | grep -q "$(docker inspect -f '{{.Id}}' "$name" 2>/dev/null || echo NONE)"; then ok=0; break; fi
  done

  if [ "$ok" = 1 ] && curl -fsS "http://127.0.0.1:$port/" | grep -qi "kasm"; then
    docker exec -d "${ENV_ARGS[@]}" "$name" /opt/izba-vnc/bin/openbox
    docker exec -d "${ENV_ARGS[@]}" "$name" /opt/izba-vnc/bin/xterm
    sleep 1
    echo "PASS: $img — web client served, X server up, WM + xterm exec'd"
    pass=$((pass+1))
  else
    echo "FAIL: $img"
    docker logs "$name" 2>&1 | tail -20 || true
    fail=$((fail+1))
    docker rm -f "$name" >/dev/null 2>&1 || true
  fi
done

echo
echo "RESULT: $pass pass, $fail fail (containers left running for manual/browser check)"
docker ps --format '{{.Names}} {{.Ports}}' | grep kvspike || true
[ "$fail" = 0 ]
