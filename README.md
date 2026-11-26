# limen-crowdstrike-autoruns

What auto-starts on every CrowdStrike fleet host, read over Real Time Response.

The fleet counterpart of the local [`autoruns`](https://github.com/CRC-BARRACUDA/limen-autoruns)
module — the same autostart locations, the same row, and the same rule that a
**disabled** entry is still listed. That last one is the point: a disabled
autostart with no business existing is one command away from running, so
`enabled` is a column and never a filter.

## How it works

Falcon has no endpoint that answers "what auto-starts on this host", so the
question is asked on the host itself: one RTR session **per host**, on a small
thread pool.

Tick the hosts, press Scan, and the list fills in as answers arrive — a spinner
beside each host while it runs, and a double-click on any finished host opens its
autoruns in a tab **while the rest are still scanning**. Stop calls off whatever
has not started.

## Where the entries come from

**Windows** — in five passes:

| Pass | Reads |
|---|---|
| machine registry | Run family (incl. WOW6432Node, `Policies\Explorer\Run`, legacy RunServices), Winlogon, Windows `Load`/`Run`/`AppInit_DLLs`, cmd `AutoRun`, Active Setup `StubPath`, image-hijack `Debugger` |
| deep registry | `BootExecute`, `AppCertDlls`, LSA security/authentication/notification packages, Winlogon `Notify` DLLs, print monitors and providers, browser helper objects (resolved to their DLL), Group Policy startup/logon/shutdown/logoff scripts, Terminal Server `StartupPrograms`, SafeBoot `AlternateShell` |
| services and tasks | services and drivers set to auto-start (disabled ones included, marked), scheduled tasks with their action, **the account they run as**, and whether they are **hidden** |
| wmi subscriptions | `__FilterToConsumerBinding` joined to its `__EventFilter` query and its `CommandLineEventConsumer` / `ActiveScriptEventConsumer` |
| per-user | the Run family, `Load`/`Run` and cmd `AutoRun` from every loaded profile hive, and every profile's Startup folder |

**Linux** — enabled systemd units with their `ExecStart`; systemd **timers**, shown
as their schedule and the unit they fire; XDG autostart (system and every home);
cron (the table, `cron.d`, the run-parts directories, every user's spool); the
**`at`** queue with each job's command; **anacron**; `rc.local`.

**macOS** — launch daemons and launch agents, system-wide and per user, plus the
`periodic` daily/weekly/monthly directories.

### Why the deeper ones are there

The Run keys are where autostart is *configured*; the second pass is where it is
*hidden*. An `AppCertDlls` entry loads into every process that creates one, a
Winlogon `Notify` DLL is told about every logon, a print monitor loads into the
spooler as SYSTEM. All of them are empty or fixed on a clean machine — which is
exactly what makes printing them worth the lines.

**WMI subscriptions** are a scheduler in every respect that matters: they run a
command when something happens, they survive reboots, they live in the CIM
repository rather than on disk, and they appear in no autoruns list that only
reads the registry and the task store.

For scheduled tasks, the account is carried in the scope, because "a task exists"
and "a task runs as SYSTEM" are different findings and the second is the one to
read first. Hidden tasks are labelled: hiding is not something a legitimate task
needs.

Per-user locations are read from **every profile**, not the one RTR runs as. On
Windows that means `HKU` by SID and every `C:\Users\*` startup folder — not
`HKCU` and `%APPDATA%`, which under RTR are SYSTEM's own and would report that
nobody on the machine has a per-user autostart. Wrong, and it looks clean.

Image-hijack Debuggers and `Policies\Explorer\Run` are in the list because
that is where persistence actually hides. They are empty on a healthy host, which
is exactly why they are worth printing.

## Five passes on Windows

The Windows work is sent as **five** `runscript` calls over one session rather
than one script.

A `runscript -Raw` command travels as a single string in a REST body and that
string is not unbounded; the combined script came to 4.8 KB, close enough to the
figures quoted for RTR that a host could refuse it. A refused script returns
*empty output*, which is indistinguishable from a machine with nothing to report
— the worst possible failure for this module. The build now refuses to emit a
pass over 4 KB, so it fails loudly in a test instead of quietly on a host.

Splitting also buys granularity: if the task store trips over one bad task, the
Run keys have already come back, and the host says which part is missing rather
than handing you a short list that looks complete. The same applies to WMI, which
is the pass most likely to be refused on a locked-down host.

## Nothing shows on the endpoint

Every PowerShell output stream is set to `SilentlyContinue`, each pass is wrapped
so an unforeseen throw cannot surface, and on Unix `stderr` is closed for the
whole script. No files are written and no window is opened. Anything that went
wrong travels back as data — a note on that host's row — not onto somebody's
screen.

Read-only throughout. But read-only is a property of the script, not of the
permission, so the permission stays the honest one — `run_hosts`. **This executes
code on your fleet.**

## It needs no privileges on your own machine

`network` and `run_hosts`, and nothing else. No `admin`, no `elevate`, no
`may_require_admin`: Limen's own process only makes HTTPS calls. The privilege it
needs is remote and Falcon-side — the RTR admin tier for `runscript` — a scope on
your API client, granted in the Falcon console.

## Requires

* The [`crowdstrike`](https://github.com/CRC-BARRACUDA/limen-crowdstrike) module,
  configured. It owns the credentials; this module owns none.
* RTR enabled, with the admin tier on the API client.

## Capability

Provides `crowdstrike.autoruns`.

```
autoruns                        -> the last scan as data
autoruns {"enabled": false}     -> only the disabled entries
autoruns {"source": "run-key"}  -> only one kind of autostart
```

It reports the last scan rather than starting one: a scan runs across the fleet
and takes minutes, which is not something another module should set off by asking
a question.

## Reports

With a report provider installed — the
[`report`](https://github.com/CRC-BARRACUDA/limen-report) module — a **Make
Report** button appears: on the fleet screen
for the last scan, with a line per host that was read — how many entries,
enabled and disabled — and a list of the hosts that were not; and in a host's
tab for that host alone, every entry its tab shows, filter included.

The button opens the provider's preview. What the document is, the ground it is
printed on and whether it is signed with your OpenPGP key are chosen there. A
host's report is filed under the host's name.

## Licence

GPL-3.0-or-later.
