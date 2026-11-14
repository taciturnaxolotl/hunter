#!/usr/bin/env bash
# Crush PreToolUse hook for hunting sessions. Lets the agent look at boxes
# over SSH but refuses anything that would change a box, so remediation
# stays a human decision (sshd/PAM/firewall changes made by an agent in a
# hurry are how scored services go red). A guardrail, not a sandbox.
cmd=${CRUSH_TOOL_INPUT_COMMAND:-}
[ -z "$cmd" ] && exit 0

# only care about commands that reach another machine
if ! grep -Eq '(^|[^a-z])(ssh|scp|sftp|rsync|sshpass)[[:space:]]|hunter[^|;&]*[[:space:]](remote|quarantine)([[:space:]]|$)' <<<"$cmd"; then
    exit 0
fi

deny() {
    echo "hunt-guard: $1. Do not run it. Show the exact command to the human with your reasoning and let them decide." >&2
    exit 2
}

grep -Eq 'hunter[^|;&]*[[:space:]]quarantine([[:space:]]|$)' <<<"$cmd" && deny "quarantine moves files on a box"
grep -Eq '(^|[^a-z])(scp|rsync|sftp)[[:space:]]' <<<"$cmd" && deny "copying files to or from a box changes state"

# strip harmless redirections before looking for writes
scrub=$(sed -E 's/[0-9]?>&[0-9]//g; s/[0-9]?>[[:space:]]*\/dev\/null//g' <<<"$cmd")

verbs='rm|mv|cp|dd|tee|truncate|shred|chattr|chmod|chown|chgrp|setcap|kill|pkill|killall|passwd|chpasswd|usermod|userdel|useradd|groupmod|gpasswd|visudo|crontab[[:space:]]+-[er]|iptables|ip6tables|nft|ufw|firewall-cmd|reboot|shutdown|poweroff|halt|init|telinit|dnf|yum|apt|apt-get|dpkg[[:space:]]+-[irP]|rpm[[:space:]]+-[eUiF]|pacman[[:space:]]+-[SRU]|mount|umount|mkfs[a-z.0-9]*|insmod|rmmod|modprobe|sed[[:space:]]+(-[a-zA-Z]*i|--in-place)|perl[[:space:]]+-[a-z]*i|ln|touch|install|wget|curl|nc|ncat|socat|python[0-9.]*|perl|bash[[:space:]]+-c|sh[[:space:]]+-c|eval|exec'
# a verb counts when it sits where a command starts: after a quote, ; | &
# ( or backtick, or right after the ssh destination (unquoted form)
pre='((sudo|env|nohup|xargs|timeout[[:space:]]+[0-9]+[a-z]?|command|busybox)[[:space:]]+)*'
if grep -Eq "(^|[;|&(\`'\"]|\\$\()[[:space:]]*$pre($verbs)([[:space:];|&)'\"\`]|$)" <<<"$scrub" ||
   grep -Eq "(ssh|sshpass)[[:space:]].*[^[:space:]]+@[^[:space:]]+[[:space:]]+$pre($verbs)([[:space:];|&)'\"\`]|$)" <<<"$scrub"; then
    deny "remote command looks state-changing"
fi
if grep -Eq 'systemctl[[:space:]]+(start|stop|restart|reload|enable|disable|mask|unmask|kill|daemon-reload|daemon-reexec|edit|set-property|isolate)' <<<"$scrub"; then
    deny "remote systemctl changes service state"
fi
if grep -Eq '>' <<<"$scrub"; then
    deny "remote command writes a file"
fi
exit 0
