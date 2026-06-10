# Rung 4: serve vsock echo on port 1025 (host connects via the UDS bridge).
# Runs in the background so /init continues to the shell after.
vsock-echo &
