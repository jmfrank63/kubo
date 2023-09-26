#!/bin/sh
USER=$(getent passwd | tail -1 | grep -oE "^([a-zA-Z0-9._]+)")
PASS=$USER
HOST=$(curl -s http://whatismyip.akamai.com/)

echo "$USER:$PASS" | chpasswd

printf "\033[0;36m"
printf "Server: %s:1080\n" "$HOST"
printf "Username: %s\n" "$USER"
printf "Password: %s\n" "$PASS"

printf "\033[0m"

printf "\033[0;33m"
echo "Test it using the following:"
echo "curl --socks5 $USER:$PASS@$HOST:1080 \\"
echo "    -L http://ifconfig.me"
printf "\033[0m"
