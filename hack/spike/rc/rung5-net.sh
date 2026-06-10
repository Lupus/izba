# Rung 5: DHCP lease from consomme, then DNS + outbound TCP via HTTP fetch.
IFACE=$(ls /sys/class/net | grep -v lo | grep -v sit0 | head -1)
if [ -z "$IFACE" ]; then echo SPIKE-RUNG5-NODEV; exit 0; fi
echo "SPIKE-RUNG5-IFACE: $IFACE"
ip link set "$IFACE" up

# Install a minimal udhcpc script so it configures the interface on lease
mkdir -p /usr/share/udhcpc
cat > /usr/share/udhcpc/default.script << 'SCRIPT'
#!/bin/sh
case "$1" in
  bound|renew)
    ip addr flush dev "$interface"
    ip addr add "$ip/$mask" dev "$interface"
    [ -n "$router" ] && ip route add default via "$router" dev "$interface"
    if [ -n "$dns" ]; then
        mkdir -p /etc
        printf 'nameserver %s\n' $dns > /etc/resolv.conf
    fi
    ;;
  deconfig)
    ip addr flush dev "$interface"
    ;;
esac
SCRIPT
chmod +x /usr/share/udhcpc/default.script

if udhcpc -i "$IFACE" -n -q 2>&1; then
    echo SPIKE-RUNG5-DHCP-OK
    ip addr show "$IFACE" | grep 'inet '
    echo "=== routes ==="
    ip route show
    echo "=== resolv.conf ==="
    cat /etc/resolv.conf 2>/dev/null || echo "(no resolv.conf)"
    # DNS probe
    if nslookup example.com >/dev/null 2>&1; then
        echo SPIKE-RUNG5-DNS-OK
    else
        echo SPIKE-RUNG5-DNS-FAIL
        nslookup example.com 2>&1 | head -3
    fi
    # TCP probe via literal IP (172.66.147.243 = example.com via Cloudflare CDN)
    if wget -T 10 -q -O - http://172.66.147.243/ >/dev/null 2>&1; then
        echo SPIKE-RUNG5-TCP-OK
    else
        echo SPIKE-RUNG5-TCP-FAIL
        wget -T 10 -O - http://172.66.147.243/ 2>&1 | head -3
    fi
    # Full HTTP via hostname
    if wget -T 10 -q -O - http://example.com >/dev/null 2>&1; then
        echo SPIKE-RUNG5-HTTP-OK
    else
        echo SPIKE-RUNG5-HTTP-FAIL
    fi
else
    echo SPIKE-RUNG5-DHCP-FAIL
fi
