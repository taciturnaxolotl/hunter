# hunter

Agentless threat hunting for competition boxes. One static binary: on your
laptop it pushes itself to every box over SSH, collects, and diffs against a
baseline; on a box it reads `/proc`, `/etc` and the package databases
directly instead of trusting the box's own `ps`, `ss`, `ls` or `lsattr`
(red team trojaned those at NCAE 2026). Nothing is installed on the boxes and
nothing is typed into a Proxmox console.

## Before competition day

```bash
./build.sh        # dist/hunter (laptop) + dist/hunter-linux-{amd64,arm64,386}
lab/run.sh                     # optional: plant the known kit in a container and watch it get caught
```

## During competition

Once a box has an IP and sshd is up:

```bash
cp hosts.example hosts.txt     # [user@]host[:port] [name], one per line
dist/hunter sweep               # first sweep of a host becomes its baseline
dist/hunter sweep --watch 30m   # later sweeps print only what changed
dist/hunter show --sev crit web # everything critical on one host
dist/hunter diff web            # baseline vs latest
dist/hunter baseline web        # accept the current state as known-good
```

In a terminal, `sweep` shows a live table of hosts filling in as they
finish, then prints the full report. With `--watch` the table stays up
between rounds: arrow keys pick a host, `enter` shows its changes, `b`
accepts its latest sweep as the baseline, `s` sweeps now, `q` quits and
prints the last round. Pipes, `--agent` and `--plain` get the plain report.

Take the baseline right after hardening. Keep re-sweeping: at CCDC 2026
implants pulled a second stage hours later onto boxes marked clean.

### On one box

When all you have is a console on the box (Proxmox, a jump host, no keys
to the others), copy the matching `hunter-linux-<arch>` over and run it
there:

```bash
sudo ./hunter                  # same as `hunter scan`
sudo ./hunter --watch 5m       # rescan every 5 minutes
sudo ./hunter quarantine       # step through the fixes
```

Every scan is saved under `~/.hunter` (or `$HUNTER_RUNS`); the first is the
baseline and later ones diff against it, so there is nothing to pipe. The
pager has two tabs: what changed, and every finding (`f` cycles crit, warn,
info). `s` scans now, `b` accepts the scan as the baseline, and `x` opens
the fix walkthrough.

The walkthrough goes through each finding from the latest scan, loudest
first, and offers only what makes sense: inspect the file, kill its
processes, quarantine it, open it in `$EDITOR`, or mark it known-good.
Nothing happens unless you pick it. Files a package owns and files every
login depends on (`/etc/shadow`, PAM config, dotfiles) are never offered
for quarantine. Known-good findings go in `~/.hunter/allow.json` and stay
in later scans as `info`, so a scoring agent or a competition kernel module
stops shouting but still shows up if it changes. A sweep from the laptop
reads the same allow list.

Digging in and cleaning up, still over SSH:

```bash
dist/hunter remote root@192.168.3.5 inspect /usr/sbin/rt-tagd             # stat, sha256, caps, ELF, strings
dist/hunter remote root@192.168.3.5 quarantine --kill /usr/sbin/rt-tagd   # move to ~/.quarantine + manifest
```

`remote ... quarantine` asks first; pass `--yes` (before the target) from
scripts.

Useful flags: `--sudo` (non-root user), `-i key`, `-o Option=value`,
`--pkg=false` (skip slow package verification), `--rules extra.json` (more
indicators), `--agent` (sanitized JSON lines for a model), `--max 0` (print
everything). Old single-dash spellings like `-sev crit` still work.
`hunter completion` and `hunter man` generate shell completions and a man
page.

## What it checks

| check | looks at |
|---|---|
| accounts | uid 0 users, NSS sources, shadow hashes, `/etc/shells`, sudoers, privileged groups |
| shells | `nologin`/`false` replaced by a real shell, chattr on critical files |
| preload | `/etc/ld.so.preload`, linker search paths |
| pam | `pam_exec`/`pam_script`, modules from odd paths or not owned by a package |
| ssh | authorized keys everywhere, `AuthorizedKeysCommand`, injected sshd options |
| systemd | units, drop-ins, LD_PRELOAD in units, per-user units, masked or empty units |
| cron | cron and at entries, root-run scripts writable by others |
| init | rc.local, profile, bashrc, alias hijacks, sshrc, history to /dev/null |
| procs | memfd or deleted executables, temp-dir binaries, fake kernel threads, LD_PRELOAD env |
| net | listeners, connections to known C2 or public IPs, raw and AF_PACKET sockets, promiscuous NICs |
| kernel | out-of-tree modules, pinned BPF objects |
| fs | SUID/SGID, file capabilities, temp-dir executables, timestomps, UPX, unowned binaries, python startup hooks |
| pkg | `rpm -Va`, `dpkg --verify`, `pacman -Qkk` |
| ioc | exact paths, strings, keys, hashes and IPs from `rules/ccdc-kit.json` |
| logs | empty or `/dev/null`'d logs, non-persistent journal |

`crit` is almost always red team, `warn` needs a human ("did we do this?"),
`info` is inventory that only matters when it changes.

## With a local model

`HUNT=1 crush` from this directory switches Crush to a local model (LM Studio
on `localhost:1234` by default, see `.crushrc` for Ollama or a teammate's
laptop), loads the `hunt` skill (`.agents/skills/hunt/`), and adds a guard
hook (`hooks/guard.sh`) that refuses SSH commands which would change a box.
The model triages and proposes; a human runs the fixes. No paid API, works
offline.

`hooks/test_guard.sh` and `go test ./...` cover the guard and the parsers
(`GOOS=linux go vet ./...` also checks the target-only code from a Mac).

## Layout

| path | what |
|---|---|
| `main.go`, `cmd_*.go` | the CLI (Cobra + Fang) |
| `internal/target` | everything that runs on a box: collect, inspect, quarantine |
| `internal/remote` | SSH: push the binary, run a subcommand, verify the transfer |
| `internal/sweep` | parallel sweeps and diffs against each baseline |
| `internal/snapshot` | observations, snapshots, diffing, the runs directory |
| `internal/report` | human (Lip Gloss) and agent (JSON lines) output |
| `internal/tui` | the live sweep view (Bubble Tea) |
| `rules` | indicator packs, `ccdc-kit.json` built in |
