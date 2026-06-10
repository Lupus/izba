# Rung 5: DHCP lease from consomme, then DNS + outbound TCP via HTTP fetch.
IFACE=$(ls /sys/class/net | grep -v lo | head -1)
if [ -z "$IFACE" ]; then echo SPIKE-RUNG5-NODEV; exit 0; fi
echo "SPIKE-RUNG5-IFACE: $IFACE"
if udhcpc -i "$IFACE" -n -q; then
    echo SPIKE-RUNG5-DHCP-OK
    ip addr show "$IFACE" | grep 'inet '
    if wget -q -O - http://example.com >/dev/null 2>&1; then
        echo SPIKE-RUNG5-HTTP-OK
    else
        echo SPIKE-RUNG5-HTTP-FAIL
    fi
else
    echo SPIKE-RUNG5-DHCP-FAIL
fi
