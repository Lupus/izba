# Upstream issue draft — OpenVMM virtio_vsock assert under stream churn

Draft for filing at microsoft/openvmm. Captures the crash izba's M0 gate
hit, the root cause, and a minimal fix. Filed in parallel with izba's
host-side mitigation (which makes the crash unreachable on the izba datapath)
and the local Plan-B patch `hack/openvmm-vsock-assert.patch`.

---

**Title:** `virtio_vsock` panics ("connection should have been removed") and
aborts the VM when a relay socket is force-closed with guest TX buffered

**Affected:** `vm/devices/virtio/virtio_vsock/src/connections.rs`. Observed on
the CI build at commit `7872712037c6ce3a03087a76207bd73cec9784a2` (x64-windows);
the same two code arms exist on `main`.

**Summary**

Under churn of short-lived guest↔host vsock stream connections, the device
thread panics:

```
thread 'basic_device_thread' panicked at
  vm\devices\virtio\virtio_vsock\src\connections.rs:1093:17:
connection should have been removed
...
ERROR openvmm_entry::vm_controller: vm worker failed error=node failure: ...
ERROR mesh_process: mesh child abnormal exit name="vm" code=0xc0000409
```

The panic aborts the entire VM worker (`0xc0000409` = STATUS_STACK_BUFFER_OVERRUN,
Rust's abort), so a guest-reachable I/O pattern takes down the whole guest.

**Root cause**

`RxReady::SendReset(key)` is handled by asserting the connection is already
gone before emitting the RST:

```rust
RxReady::SendReset(key) => {
    assert!(
        !self.conns.contains_key(&key),
        "connection should have been removed"
    );
    (Some(new_rst_packet(self.guest_cid, key)), PendingFutures::NONE)
}
```

But two error arms queue `RxReady::SendReset(...)` **without** removing the
connection first:

1. `handle_write_ready`, the `write_from_buffer()` error arm (~line 988):

   ```rust
   Err(err) => {
       tracelimit::warn_ratelimited!(..., "failed to write buffered data to host socket on write ready");
       PendingFutures::simple_rx(RxReady::SendReset(id.key)) // conn still in self.conns
   }
   ```

2. `handle_shutdown_packet`, the `handle_shutdown()` error arm (~line 862):

   ```rust
   if let Err(err) = conn.handle_shutdown(header.shutdown_flags()) {
       tracelimit::warn_ratelimited!(..., "failed to shutdown connection");
       PendingFutures::simple_rx(RxReady::SendReset(key)) // conn still in self.conns
   }
   ```

When either fires, the connection remains in `self.conns`; the next poll of
the queued `RxReady::SendReset` hits the assert and aborts.

(For contrast, every *other* `SendReset` producer removes first — the
`handle_guest_tx` catch-all calls `remove_connection` when `err.remove`, the
`complete_host_connection` error arm calls `remove_connection`, and the
clean-shutdown branches call `remove_connection` before `SendReset`.)

**Reliable trigger**

A host-side relay socket that is force-closed (Windows `WSAECONNRESET`, os
error 10054; Linux `ECONNRESET`) while the guest still has buffered TX. The
device tries to flush the buffered guest bytes to the now-dead relay socket,
`write_from_buffer()` returns the reset error, arm (1) fires, and the assert
trips on the next poll. The VM log shows the write failure immediately before
the panic:

```
WARN virtio_vsock::connections: failed to write buffered data to host socket
  on write ready error=...forcibly closed... (os error 10054) ... seq: 4b1
thread 'basic_device_thread' panicked at ...connections.rs:1093:17:
connection should have been removed
```

**Reproduction** (what we did)

A host client repeatedly: opens a vsock stream to a guest service that
immediately blasts a burst, reads one chunk, stops reading so the relay
socket buffer fills, then drops the connection abruptly while the guest still
has bytes queued. After a few dozen such cycles the VM aborts. (In izba this
is `ttystorm chop --direct`; any client that abandons a relay socket mid-TX
will do.)

**Fix**

Remove the connection before queueing `SendReset` in both arms — mirroring the
other producers. Two-line change plus comments; see the diff below. This makes
the assert's invariant hold by construction.

```diff
@@ handle_shutdown_packet, handle_shutdown() error arm @@
                 "failed to shutdown connection"
             );
+            self.remove_connection(&key);
             PendingFutures::simple_rx(RxReady::SendReset(key))

@@ handle_write_ready, write_from_buffer() error arm @@
                 "failed to write buffered data to host socket on write ready"
             );
+            self.remove_connection(&id.key);
             PendingFutures::simple_rx(RxReady::SendReset(id.key))
```

Alternatively the `RxReady::SendReset` handler could tolerate an
already-removed *or* still-present connection (remove-if-present instead of
assert), but removing at the source keeps the single ownership rule the rest
of the file already follows.

**Severity**

A guest-reachable traffic pattern aborts the whole VM. Even if a misbehaving
host relay is "the host's fault", the device should reset the offending
connection, not panic the guest.
