# Rung 4: serve vsock echo on port 1025 (host connects via the UDS bridge).
# Stays in foreground in the background job; init still drops to a shell after.
vsock-echo &
