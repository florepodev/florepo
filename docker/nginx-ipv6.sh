#!/bin/sh
# Docker Desktop forwards host IPv6 connections (e.g. http://localhost:8080 -> [::1]) to the container's IPv6
# address, so nginx must listen on [::] as well. Drop that listener when IPv6 is disabled in the container.
if ! grep -q . /proc/net/if_inet6 2>/dev/null; then
    sed -i '/listen \[::\]:8080/d' /etc/nginx/templates/nginx.conf.template
    echo "$0: IPv6 not available, listening on IPv4 only"
fi
