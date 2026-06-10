# Rung 3: mount the virtio-fs share (tag "ws"), prove both directions.
if mount -t virtiofs ws /mnt; then
    echo SPIKE-RUNG3-MOUNT-OK
    if [ -f /mnt/host-file.txt ]; then
        echo "SPIKE-RUNG3-READ-OK: $(cat /mnt/host-file.txt)"
    else
        echo SPIKE-RUNG3-READ-FAIL
    fi
    echo guest-was-here > /mnt/guest-file.txt \
        && echo SPIKE-RUNG3-WRITE-OK || echo SPIKE-RUNG3-WRITE-FAIL
else
    echo SPIKE-RUNG3-MOUNT-FAIL
fi
