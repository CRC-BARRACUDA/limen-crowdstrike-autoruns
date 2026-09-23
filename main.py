"""crowdstrike-autoruns — what auto-starts on every fleet host, over RTR.

The fleet counterpart of the local ``autoruns`` module: the same autostart
locations, the same row, the same rule that a **disabled** entry is still listed.
That last one is the point of the module — a disabled autostart with no business
existing is one command away from running, so `enabled` is a column and never a
filter.

It owns no credentials. Auth and the host list come from the ``crowdstrike``
capability; this module only knows how to ask a host what starts on it.

How it gets there
-----------------
Falcon has no endpoint that answers "what auto-starts on this host", so the
question is asked on the host itself: an RTR session **per host** and one
``runscript`` for its platform, printing one entry per line. One session per host
rather than one batch across many is the point of the screen — a batch returns
when its slowest member does, while here each host lands on its own and can be
opened while the rest are still going.

Read-only: the registry, the task store, ``/etc`` and the launch directories are
inspected and nothing is changed.

Where the entries come from
---------------------------
* **Windows** — the Run family (including the WOW6432Node and Policies views and
  the legacy RunServices), Winlogon, the Windows load/run values, the cmd
  processor AutoRun, Active Setup StubPaths, image-hijack Debuggers, services and
  drivers set to auto-start, the scheduled tasks, and both Startup folders.
* **Linux** — enabled systemd units, XDG autostart (system and every home), cron
  (the table, the drop-in dir, the run-parts dirs, every user's spool), and
  ``rc.local``.
* **macOS** — launch daemons and launch agents, system-wide and per user.

Per-user locations are read from **every profile**, not the invoking one: RTR
runs as SYSTEM (or root), so its own hive and home are not the question. On
Windows that means HKU by SID rather than HKCU — reading HKCU would report that
nobody on the machine has a per-user autostart, which is wrong and looks clean.

Methods
-------
  ui              -> the screen: fetch hosts, tick them, scan
  fetch           -> load the reachable inventory from ``crowdstrike``
  scan_selected   -> enumerate the ticked hosts
  scan_all        -> enumerate every listed host
  progress        -> one tick of the progress loop
  stop            -> call off what has not started
  open_host       -> one host's autoruns, in a tab (the double-click target)
  about           -> one entry, in a tab
  autoruns        -> the same data as JSON, for other modules
"""

import json
import os
import queue
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from limen_sdk import (
    Button,
    Catalog,
    Checkbox,
    Label,
    MenuItem,
    Module,
    Row,
    Separator,
    Table,
    Text,
    Window,
)

# The module's own strings. `host.locale()` is asked per render rather than
# once at start: the language is the application's setting and can change
# while the module is running.
CAT = Catalog.from_dir(os.path.dirname(os.path.abspath(__file__)), ("en", "uk"))
_lang = {"code": "en"}


def t(key, **args):
    """Translate for the language the host last reported."""
    return CAT.tr(_lang["code"], key, **args)


def _sync_locale():
    """Re-read the host's language before drawing.

    Asked each time rather than once at start, because it is the
    application's setting and the user can change it while the module is
    open. One round-trip per render, which is what the Rust modules do too.
    """
    try:
        _lang["code"] = m.host.locale()
    except Exception:  # noqa: BLE001
        pass  # keep the last language rather than failing to draw


CAP = "crowdstrike.autoruns"
m = Module("crowdstrike-autoruns", [CAP])

# The fetched inventory. Held so reopening the tab restores the list rather than
# re-querying the fleet.
_hosts = {"rows": None}
_status = {"msg": ""}

# Per-host scan state, the only thing shared between the worker threads and the
# dispatch thread — so every read and write of it takes `_lock`.
#
#   _jobs[host_id] = {hostname, platform, state, autoruns, error, notes}
#   state: "queued" | "scanning" | "done" | "failed" | "stopped"
_jobs = {}
_lock = threading.Lock()

# Workers must not log through `host`: the SDK's host bridge writes a frame to
# stdout and then reads stdin, and that is the JSON-RPC pipe. A second thread
# using it interleaves a write into the protocol and steals a line of the
# response. So workers put their lines here and the dispatch thread drains them
# on the next poll, where logging is safe.
_logq = queue.Queue()

# The running scan: the pool doing the work, and the flag that calls it off.
_run = {"pool": None, "stop": None, "started": 0.0}

# One host at a time per thread, and few enough threads not to be rate-limited
# off the Falcon API — the aim is that a small fleet finishes quickly, not that a
# large one arrives all at once.
MAX_WORKERS = 8

# A scan of a large fleet returns a lot of rows, and every one of them crosses
# the RTR response, this process, and the UI — so there is a cap per host.
#
# Set far higher than the device list's, because the shape of the data is
# different: a Windows host has tens to a few hundred entries in Add/Remove
# Programs, but an ordinary Linux host carries two to four thousand packages, and
# a cap of a few hundred would silently report a fraction of the machine and call
# it the answer. When it does bite, the host says so on its own row.
MAX_ROWS_PER_HOST = 5000

# How long the script itself may run on the endpoint. Falcon caps this at 600.
RTR_TIMEOUT = 600

# The most one `runscript -Raw` may carry. The command travels as a single string
# in a REST body, and the figures quoted for RTR sit around 4 KB — so this is set
# below that and enforced when the script is built, where it is a loud failure in
# a test, rather than discovered on a host as empty output.
MAX_SCRIPT_BYTES = 4000

# How long a poll waits before answering. The host re-invokes an `auto` action as
# soon as the view renders, so without this the progress loop would spin as fast
# as the two processes can exchange frames, for as long as the scan lasts.
POLL_SECONDS = 0.6


class _Stopped(Exception):
    """Raised inside a worker when Stop was pressed — a cancellation, not a
    failure, and shown as one."""


class _UnknownOS(Exception):
    """The host's OS is not one this module can read, so nothing is run on it."""

    def __init__(self, platform):
        super().__init__(f"unsupported OS: {platform}")
        self.platform = platform


# --------------------------------------------------------------------------- #
# Falcon RTR (auth and the inventory come from the crowdstrike capability).
# --------------------------------------------------------------------------- #
def _http(method, url, token, body=None):
    headers = {"Authorization": f"Bearer {token}"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, method=method, headers=headers, data=data)
    # Walking three registry views (or four package databases) takes longer
    # than a notification does, so the read timeout is generous.
    with urllib.request.urlopen(req, timeout=120) as resp:
        raw = resp.read().decode("utf-8")
        return resp.status, (json.loads(raw) if raw else {})


def _auth(host):
    """Bearer token + API base from the crowdstrike capability."""
    token = (host.call("crowdstrike", "token", {}) or {}).get("token")
    base = (
        (host.call("crowdstrike", "api", {}) or {})
        .get("base_url", "https://api.crowdstrike.com")
        .rstrip("/")
    )
    if not token:
        raise RuntimeError(
            "no CrowdStrike token — configure the crowdstrike module first"
        )
    return token, base


def _rtr_one(hid, platform, token, base, stop):
    """Enumerate ONE host and return its stdout.

    One RTR session per host rather than one batch across many: a batch returns
    when its slowest member does, and this module's whole point is that a finished
    host is usable while the others are still going. The cost is an init call per
    host, which is what the thread pool is for.

    Raises on failure — the caller turns that into the host's error state. Never
    touches `host`: this runs on a worker thread, and the SDK's host bridge is the
    JSON-RPC pipe on stdio, which only the dispatch thread may write to.
    """
    if stop.is_set():
        raise _Stopped()
    # Chosen first, so a host whose OS we cannot read costs no RTR session and
    # nothing is run on it.
    passes = _script_for(platform)
    st, init = _http(
        "POST",
        f"{base}/real-time-response/combined/batch-init-session/v1",
        token,
        {"host_ids": [hid], "timeout": 120},
    )
    batch_id = init.get("batch_id")
    if not batch_id:
        raise RuntimeError(f"no RTR session (RTR enabled for this host?) HTTP {st}")
    resources = init.get("resources") or {}
    if isinstance(resources, dict):
        for r in resources.values():
            for e in r.get("errors") or []:
                raise RuntimeError(str(e.get("message", e)))

    # One session, then each pass over it. Their outputs are concatenated: the
    # parser only ever sees lines, so it neither knows nor needs to know that they
    # arrived in several pieces.
    collected, troubles = [], []
    for label, script in passes:
        if stop.is_set():
            raise _Stopped()
        # `-Timeout` before `-Raw`: the raw block ends at a fence, and anything
        # after that fence is ambiguous, so no argument goes there.
        command_string = f"runscript -Timeout={RTR_TIMEOUT} -Raw=```" + script + "```"
        st, res = _http(
            "POST",
            f"{base}/real-time-response/combined/batch-admin-command/v1",
            token,
            {
                "batch_id": batch_id,
                "base_command": "runscript",
                "command_string": command_string,
            },
        )
        per_host = (res.get("combined", {}).get("resources", {}) or {}).get(hid)
        if per_host is None:
            troubles.append(f"{label}: no answer (HTTP {st})")
            continue
        stdout = per_host.get("stdout") or ""
        if "#begin" in stdout:
            collected.append(stdout)
            continue
        # The script prints `#begin` before doing anything, so its absence does
        # not mean "nothing here" — it means the pass did not run. One pass
        # failing is not the host failing, so it is recorded and the rest go on.
        stderr = (per_host.get("stderr") or "").strip()
        errs = "; ".join(str(e.get("message", e)) for e in per_host.get("errors") or [])
        troubles.append(f"{label}: {errs or stderr or 'did not run'}")

    if not collected:
        # Every pass failed, so there is nothing to show and a reason to give.
        raise RuntimeError("; ".join(troubles) or "the script did not run on this host")
    if troubles:
        # Some of the picture is missing, and the operator has to know which part
        # rather than be handed a short list that looks complete.
        collected.append("#err=" + "; ".join(troubles) + "\n")
    return "\n".join(collected)


# --------------------------------------------------------------------------- #
# The enumeration scripts.
#
# Each prints one entry per line as
#     source|name|command|location|scope|enabled
# plus `#`-prefixed metadata lines. A flat line format rather than JSON on
# purpose: RTR hands back stdout as loose text and truncates it, and a truncated
# JSON document is worth nothing while a truncated list of lines is worth all but
# the last line.
#
# **No backticks.** The script is sent inside an RTR ```...``` block, and a
# backtick is also PowerShell's escape character — one in here corrupts the
# command on the wire, so the Windows script escapes nothing and quotes with
# single quotes throughout.
# --------------------------------------------------------------------------- #

# Windows, in three passes. See `_PASSES` for why it is split rather than one
# script: each pass is a whole script of its own, preamble included.
_WIN_MACHINE_REGISTRY = r"""
Write-Output '#begin'
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$n = 0
function Clean($s) {
  if ($null -eq $s) { return '' }
  return (([string]$s) -replace '[\r\n\|]', ' ').Trim()
}
function Row($src, $name, $cmd, $loc, $scope, $on) {
  return (@($src, (Clean $name), (Clean $cmd), (Clean $loc), $scope, $on) -join '|')
}
function Emit($line) {
  if ($script:n -ge __LIMIT__) { Write-Output '#truncated'; exit }
  $script:n = $script:n + 1
  Write-Output $line
}
function Values($path, $src, $scope, $only) {
  if (-not (Test-Path $path)) { return }
  $k = Get-Item $path
  foreach ($v in $k.GetValueNames()) {
    if ($v -eq '') { continue }
    if ($only -and ($only -notcontains $v)) { continue }
    Emit (Row $src $v $k.GetValue($v) $path $scope '1')
  }
}
$runKeys = @(
  '\Software\Microsoft\Windows\CurrentVersion\Run',
  '\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  '\Software\Microsoft\Windows\CurrentVersion\RunOnceEx',
  '\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
  '\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
  '\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
  '\Software\Microsoft\Windows\CurrentVersion\RunServices',
  '\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
)
try {
foreach ($r in $runKeys) { Values ('HKLM:' + $r) 'run-key' 'system' $null }
Values 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'winlogon' 'system' @('Shell','Userinit','Taskman','AppSetup')
Values 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows' 'windows-load' 'system' @('Load','Run','AppInit_DLLs')
Values 'HKLM:\Software\Microsoft\Command Processor' 'cmd-autorun' 'system' @('AutoRun')

# Active Setup: a StubPath runs once per user at logon.
$as = 'HKLM:\Software\Microsoft\Active Setup\Installed Components'
if (Test-Path $as) {
  foreach ($c in @(Get-ChildItem $as)) {
    $stub = Clean (Get-ItemProperty $c.PSPath).StubPath
    if ($stub) { Emit (Row 'active-setup' $c.PSChildName $stub $c.Name 'system' '1') }
  }
}
# Image File Execution Options: a Debugger value hijacks the named program.
$ifeo = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
if (Test-Path $ifeo) {
  foreach ($e in @(Get-ChildItem $ifeo)) {
    $dbg = Clean (Get-ItemProperty $e.PSPath).Debugger
    if ($dbg) { Emit (Row 'image-hijack' $e.PSChildName $dbg $e.Name 'system' '1') }
  }
}
} catch { Write-Output ('#err=' + ($_.Exception.Message -replace '[\r\n\|]', ' ')) }
"""

_WIN_SERVICES_TASKS = r"""
Write-Output '#begin'
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$n = 0
function Clean($s) {
  if ($null -eq $s) { return '' }
  return (([string]$s) -replace '[\r\n\|]', ' ').Trim()
}
function Row($src, $name, $cmd, $loc, $scope, $on) {
  return (@($src, (Clean $name), (Clean $cmd), (Clean $loc), $scope, $on) -join '|')
}
function Emit($line) {
  if ($script:n -ge __LIMIT__) { Write-Output '#truncated'; exit }
  $script:n = $script:n + 1
  Write-Output $line
}
function Values($path, $src, $scope, $only) {
  if (-not (Test-Path $path)) { return }
  $k = Get-Item $path
  foreach ($v in $k.GetValueNames()) {
    if ($v -eq '') { continue }
    if ($only -and ($only -notcontains $v)) { continue }
    Emit (Row $src $v $k.GetValue($v) $path $scope '1')
  }
}
$runKeys = @(
  '\Software\Microsoft\Windows\CurrentVersion\Run',
  '\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  '\Software\Microsoft\Windows\CurrentVersion\RunOnceEx',
  '\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
  '\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
  '\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
  '\Software\Microsoft\Windows\CurrentVersion\RunServices',
  '\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
)
try {
# Services and drivers set to start automatically (Start = 2). Disabled ones are
# reported too, as not-enabled: a disabled service that should not exist is still
# worth seeing.
$svc = 'HKLM:\System\CurrentControlSet\Services'
if (Test-Path $svc) {
  foreach ($e in @(Get-ChildItem $svc)) {
    $p = Get-ItemProperty $e.PSPath
    if ($null -eq $p.Start) { continue }
    if ($p.Start -ne 2 -and $p.Start -ne 4) { continue }
    $on = '1'
    if ($p.Start -eq 4) { $on = '0' }
    $path = Clean $p.ImagePath
    if (-not $path) { $path = Clean $p.ServiceDll }
    Emit (Row 'service' $e.PSChildName $path $e.Name 'system' $on)
  }
}
# Scheduled tasks. Get-ScheduledTask carries the state, the action and the
# principal, none of which reading the task XML off disk gives you.
#
# The account the task runs as goes in the scope, because "a task exists" and "a
# task runs as SYSTEM" are different findings, and the second is the one worth
# reading first. A hidden task is called out the same way: hiding is not a
# feature anybody legitimate needs.
foreach ($t in @(Get-ScheduledTask)) {
  $on = '1'
  if ($t.State -eq 'Disabled') { $on = '0' }
  $act = ''
  foreach ($a in @($t.Actions)) {
    if ($a.Execute) { $act = (Clean $a.Execute) + ' ' + (Clean $a.Arguments) }
    if ($a.ClassId) { $act = 'com: ' + (Clean $a.ClassId) }
  }
  $who = ''
  if ($t.Principal) {
    $who = Clean $t.Principal.UserId
    if (-not $who) { $who = Clean $t.Principal.GroupId }
  }
  $scope = 'system'
  if ($who) { $scope = 'user:' + $who }
  $name = Clean $t.TaskName
  if ($t.Settings -and $t.Settings.Hidden) { $name = $name + ' (hidden)' }
  Emit (Row 'scheduled-task' $name $act ($t.TaskPath) $scope $on)
}
} catch { Write-Output ('#err=' + ($_.Exception.Message -replace '[\r\n\|]', ' ')) }
"""

_WIN_PER_USER = r"""
Write-Output '#begin'
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$n = 0
function Clean($s) {
  if ($null -eq $s) { return '' }
  return (([string]$s) -replace '[\r\n\|]', ' ').Trim()
}
function Row($src, $name, $cmd, $loc, $scope, $on) {
  return (@($src, (Clean $name), (Clean $cmd), (Clean $loc), $scope, $on) -join '|')
}
function Emit($line) {
  if ($script:n -ge __LIMIT__) { Write-Output '#truncated'; exit }
  $script:n = $script:n + 1
  Write-Output $line
}
function Values($path, $src, $scope, $only) {
  if (-not (Test-Path $path)) { return }
  $k = Get-Item $path
  foreach ($v in $k.GetValueNames()) {
    if ($v -eq '') { continue }
    if ($only -and ($only -notcontains $v)) { continue }
    Emit (Row $src $v $k.GetValue($v) $path $scope '1')
  }
}
$runKeys = @(
  '\Software\Microsoft\Windows\CurrentVersion\Run',
  '\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  '\Software\Microsoft\Windows\CurrentVersion\RunOnceEx',
  '\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
  '\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
  '\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
  '\Software\Microsoft\Windows\CurrentVersion\RunServices',
  '\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
)
try {
# Per-user: every loaded profile hive, by SID. The _Classes hives are class
# registrations rather than profiles, so they are skipped.
New-PSDrive -Name HKUsers -PSProvider Registry -Root HKEY_USERS | Out-Null
foreach ($u in @(Get-ChildItem 'HKUsers:\')) {
  $sid = $u.PSChildName
  if ($sid -notlike 'S-1-5-21-*') { continue }
  if ($sid -like '*_Classes') { continue }
  $who = $sid
  try {
    $acct = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
    if ($acct) { $who = Clean $acct }
  } catch { }
  foreach ($r in $runKeys) { Values ('HKUsers:\' + $sid + $r) 'run-key' ('user:' + $who) $null }
  Values ('HKUsers:\' + $sid + '\Software\Microsoft\Windows NT\CurrentVersion\Windows') 'windows-load' ('user:' + $who) @('Load','Run')
  Values ('HKUsers:\' + $sid + '\Software\Microsoft\Command Processor') 'cmd-autorun' ('user:' + $who) @('AutoRun')
}
# Startup folders: the all-users one, and every profile's own.
$folders = @()
if ($env:ProgramData) {
  $folders += , @(($env:ProgramData + '\Microsoft\Windows\Start Menu\Programs\StartUp'), 'system')
}
$users = 'C:\Users'
if ($env:SystemDrive) { $users = $env:SystemDrive + '\Users' }
if (Test-Path $users) {
  foreach ($d in @(Get-ChildItem $users -Directory)) {
    $folders += , @(($d.FullName + '\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'), ('user:' + $d.Name))
  }
}
foreach ($f in $folders) {
  if (-not (Test-Path $f[0])) { continue }
  foreach ($item in @(Get-ChildItem $f[0] -File)) {
    if ($item.Name -eq 'desktop.ini') { continue }
    Emit (Row 'startup-folder' $item.BaseName $item.FullName $f[0] $f[1] '1')
  }
}
} catch { Write-Output ('#err=' + ($_.Exception.Message -replace '[\r\n\|]', ' ')) }
"""


# Linux: the three the local module reads — systemd, XDG autostart, cron — plus
# rc.local, which is old but still where things get parked.
#
# Per-user XDG and per-user crontabs are read from every home and from the cron
# spool rather than from the invoking user's, for the same reason as the Windows
# hives: RTR runs as root, and root's own autostart is not the question.
_WIN_DEEP_REGISTRY = r"""
Write-Output '#begin'
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$n = 0
function Clean($s) {
  if ($null -eq $s) { return '' }
  return (([string]$s) -replace '[\r\n\|]', ' ').Trim()
}
function Row($src, $name, $cmd, $loc, $scope, $on) {
  return (@($src, (Clean $name), (Clean $cmd), (Clean $loc), $scope, $on) -join '|')
}
function Emit($line) {
  if ($script:n -ge __LIMIT__) { Write-Output '#truncated'; exit }
  $script:n = $script:n + 1
  Write-Output $line
}
function Values($path, $src, $scope, $only) {
  if (-not (Test-Path $path)) { return }
  $k = Get-Item $path
  foreach ($v in $k.GetValueNames()) {
    if ($v -eq '') { continue }
    if ($only -and ($only -notcontains $v)) { continue }
    Emit (Row $src $v $k.GetValue($v) $path $scope '1')
  }
}
try {
# ---- registry autostarts that are not the Run keys -------------------------- #
# These are where persistence actually lives once it is trying not to be found:
# a DLL loaded into every process, a package the security subsystem loads at
# boot, a print monitor driver. All of them are empty or fixed on a clean host,
# which is what makes printing them worth the lines.
function Multi($path, $name, $src) {
  if (-not (Test-Path $path)) { return }
  $v = (Get-ItemProperty $path).$name
  if (-not $v) { return }
  foreach ($one in @($v)) {
    $one = Clean $one
    if ($one) { Emit (Row $src $name $one $path 'system' '1') }
  }
}
$sm = 'HKLM:\System\CurrentControlSet\Control\Session Manager'
Multi $sm 'BootExecute' 'boot-execute'
Multi $sm 'AppCertDlls' 'appcert-dll'
Multi ($sm + '\AppCertDlls') 'AppCertDlls' 'appcert-dll'
Values ($sm + '\AppCertDlls') 'appcert-dll' 'system' $null
$lsa = 'HKLM:\System\CurrentControlSet\Control\Lsa'
Multi $lsa 'Security Packages' 'lsa-package'
Multi $lsa 'Authentication Packages' 'lsa-package'
Multi $lsa 'Notification Packages' 'lsa-package'
Multi ($lsa + '\OSConfig') 'Security Packages' 'lsa-package'
# Winlogon Notify: a DLL told about every logon. Legacy, and still honoured.
$nfy = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify'
if (Test-Path $nfy) {
  foreach ($e in @(Get-ChildItem $nfy)) {
    $dll = Clean (Get-ItemProperty $e.PSPath).DllName
    if ($dll) { Emit (Row 'winlogon-notify' $e.PSChildName $dll $e.Name 'system' '1') }
  }
}
# Print monitors and providers load into the spooler, which runs as SYSTEM.
foreach ($base in @('HKLM:\System\CurrentControlSet\Control\Print\Monitors',
                    'HKLM:\System\CurrentControlSet\Control\Print\Providers')) {
  if (-not (Test-Path $base)) { continue }
  foreach ($e in @(Get-ChildItem $base)) {
    $drv = Get-ItemProperty $e.PSPath
    $d = Clean $drv.Driver
    if (-not $d) { $d = Clean $drv.Name }
    if ($d) { Emit (Row 'print-monitor' $e.PSChildName $d $e.Name 'system' '1') }
  }
}
# Browser helper objects load into anything hosting the web control.
$bho = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'
if (Test-Path $bho) {
  foreach ($e in @(Get-ChildItem $bho)) {
    $clsid = $e.PSChildName
    $dll = ''
    foreach ($r in @('HKLM:\Software\Classes\CLSID\', 'HKLM:\Software\Classes\WOW6432Node\CLSID\')) {
      $ip = $r + $clsid + '\InprocServer32'
      if (Test-Path $ip) { $dll = Clean (Get-Item $ip).GetValue('') }
      if ($dll) { break }
    }
    Emit (Row 'browser-helper' $clsid $dll $e.Name 'system' '1')
  }
}
# Group Policy logon/startup scripts, and the Terminal Server initial program.
foreach ($when in @('Startup', 'Logon', 'Shutdown', 'Logoff')) {
  $gp = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\' + $when
  if (-not (Test-Path $gp)) { continue }
  foreach ($e in @(Get-ChildItem $gp -Recurse)) {
    $sc = Clean (Get-ItemProperty $e.PSPath).Script
    if ($sc) { Emit (Row 'gp-script' $when $sc $e.Name 'system' '1') }
  }
}
Values 'HKLM:\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd' 'terminal-server' 'system' @('StartupPrograms')
Values 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'safeboot-shell' 'system' @('AlternateShell')
} catch { Write-Output ('#err=' + ($_.Exception.Message -replace '[\r\n\|]', ' ')) }
"""

_WIN_WMI = r"""
Write-Output '#begin'
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$n = 0
function Clean($s) {
  if ($null -eq $s) { return '' }
  return (([string]$s) -replace '[\r\n\|]', ' ').Trim()
}
function Row($src, $name, $cmd, $loc, $scope, $on) {
  return (@($src, (Clean $name), (Clean $cmd), (Clean $loc), $scope, $on) -join '|')
}
function Emit($line) {
  if ($script:n -ge __LIMIT__) { Write-Output '#truncated'; exit }
  $script:n = $script:n + 1
  Write-Output $line
}
function Values($path, $src, $scope, $only) {
  if (-not (Test-Path $path)) { return }
  $k = Get-Item $path
  foreach ($v in $k.GetValueNames()) {
    if ($v -eq '') { continue }
    if ($only -and ($only -notcontains $v)) { continue }
    Emit (Row $src $v $k.GetValue($v) $path $scope '1')
  }
}
try {
# ---- WMI event subscriptions ------------------------------------------------ #
# A filter bound to a consumer is a scheduler in every respect that matters: it
# runs a command when something happens, it survives reboots, it lives in the
# CIM repository rather than on disk, and it appears in no autoruns list that
# only reads the registry and the task store. Close to absent on a clean host,
# which is why an entry here is worth more than most.
$ns = 'root\Subscription'
foreach ($b in @(Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding)) {
  $consumer = Clean $b.Consumer
  $filter = Clean $b.Filter
  $query = ''
  $cmd = ''
  foreach ($f in @(Get-WmiObject -Namespace $ns -Class __EventFilter)) {
    if ($consumer -and ($filter -like ('*' + $f.Name + '*'))) { $query = Clean $f.Query }
  }
  foreach ($c in @(Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer)) {
    if ($consumer -like ('*' + $c.Name + '*')) {
      $cmd = (Clean $c.ExecutablePath) + ' ' + (Clean $c.CommandLineTemplate)
    }
  }
  foreach ($c in @(Get-WmiObject -Namespace $ns -Class ActiveScriptEventConsumer)) {
    if ($consumer -like ('*' + $c.Name + '*')) {
      $cmd = 'script: ' + (Clean $c.ScriptFileName) + ' ' + (Clean $c.ScriptText)
    }
  }
  if (-not $cmd) { $cmd = $consumer }
  Emit (Row 'wmi-subscription' $filter $cmd $query 'system' '1')
}
} catch { Write-Output ('#err=' + ($_.Exception.Message -replace '[\r\n\|]', ' ')) }
"""


_LINUX = r"""
exec 2>/dev/null
echo '#begin'
LIMIT=__LIMIT__
n=0
emit() {
  n=$((n+1))
  if [ "$n" -gt "$LIMIT" ]; then echo '#truncated'; exit 0; fi
  printf '%s|%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$5" "$6"
}
clean() { printf '%s' "$1" | tr -d '|' | tr -d '\r\n'; }

# systemd: enabled units of the kinds that start something. A .timer has no
# ExecStart of its own — it triggers another unit on a schedule — so for those
# the schedule and the unit it fires are the command, which is the useful answer.
if command -v systemctl >/dev/null 2>&1; then
  systemctl list-unit-files --state=enabled --type=service,timer,socket,path \
      --no-legend --no-pager 2>/dev/null |
    while read -r unit state _rest; do
      [ -n "$unit" ] || continue
      body=$(systemctl cat "$unit" 2>/dev/null)
      what=$(printf '%s' "$body" | sed -n 's/^ExecStart=//p' | head -1)
      src=systemd
      case "$unit" in
        *.timer)
          src=systemd-timer
          when=$(printf '%s' "$body" | sed -n 's/^OnCalendar=//p' | head -1)
          [ -n "$when" ] || when=$(printf '%s' "$body" | sed -n 's/^OnBootSec=//p' | head -1)
          fires=$(printf '%s' "$body" | sed -n 's/^Unit=//p' | head -1)
          [ -n "$fires" ] || fires=$(printf '%s' "$unit" | sed 's/\.timer$/.service/')
          what="$when -> $fires"
          ;;
      esac
      emit "$src" "$(clean "$unit")" "$(clean "$what")" "$(clean "$unit")" system 1
    done
fi

# at: one-off jobs queued for later. atq lists them; at -c prints the body, whose
# last non-empty line is the command itself.
if command -v atq >/dev/null 2>&1; then
  atq 2>/dev/null | while read -r job rest; do
    [ -n "$job" ] || continue
    cmd=$(at -c "$job" 2>/dev/null | grep -v '^[[:space:]]*$' | tail -1)
    emit at "job $(clean "$job")" "$(clean "$cmd")" "$(clean "$rest")" system 1
  done
fi

# anacron: catches up on jobs the machine was off for.
if [ -f /etc/anacrontab ]; then
  grep -v '^[[:space:]]*#' /etc/anacrontab 2>/dev/null | grep -v '^[[:space:]]*$' |
    grep -v '^[A-Z_]*=' | while read -r line; do
      emit anacron "$(clean "$(printf '%s' "$line" | awk '{print $3}')")" \
           "$(clean "$line")" /etc/anacrontab system 1
    done
fi

# XDG autostart: the system-wide directories, then every home.
for dir in /etc/xdg/autostart /usr/share/gnome/autostart; do
  [ -d "$dir" ] || continue
  for f in "$dir"/*.desktop; do
    [ -f "$f" ] || continue
    nm=$(sed -n 's/^Name=//p' "$f" | head -1)
    ex=$(sed -n 's/^Exec=//p' "$f" | head -1)
    hidden=$(sed -n 's/^Hidden=//p' "$f" | head -1)
    on=1
    [ "$hidden" = "true" ] && on=0
    emit xdg-autostart "$(clean "${nm:-$(basename "$f")}")" "$(clean "$ex")" "$(clean "$f")" system "$on"
  done
done
for home in /home/* /root; do
  [ -d "$home/.config/autostart" ] || continue
  who=$(basename "$home")
  for f in "$home"/.config/autostart/*.desktop; do
    [ -f "$f" ] || continue
    nm=$(sed -n 's/^Name=//p' "$f" | head -1)
    ex=$(sed -n 's/^Exec=//p' "$f" | head -1)
    hidden=$(sed -n 's/^Hidden=//p' "$f" | head -1)
    on=1
    [ "$hidden" = "true" ] && on=0
    emit xdg-autostart "$(clean "${nm:-$(basename "$f")}")" "$(clean "$ex")" "$(clean "$f")" "user:$who" "$on"
  done
done

# cron: the system table, the drop-in directory, the run-parts directories, and
# every user's spool.
for f in /etc/crontab /etc/cron.d/*; do
  [ -f "$f" ] || continue
  grep -v '^[[:space:]]*#' "$f" 2>/dev/null | grep -v '^[[:space:]]*$' |
    while read -r line; do
      emit cron "$(clean "$f")" "$(clean "$line")" "$(clean "$f")" system 1
    done
done
for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
  [ -d "$dir" ] || continue
  for f in "$dir"/*; do
    [ -f "$f" ] || continue
    emit cron "$(clean "$(basename "$f")")" "$(clean "$f")" "$(clean "$dir")" system 1
  done
done
for spool in /var/spool/cron/crontabs/* /var/spool/cron/*; do
  [ -f "$spool" ] || continue
  who=$(basename "$spool")
  grep -v '^[[:space:]]*#' "$spool" 2>/dev/null | grep -v '^[[:space:]]*$' |
    while read -r line; do
      emit cron "$(clean "$who")" "$(clean "$line")" "$(clean "$spool")" "user:$who" 1
    done
done

# rc.local: only when it is there and executable, which is the only way it runs.
if [ -x /etc/rc.local ]; then
  emit rc-local rc.local /etc/rc.local /etc/rc.local system 1
fi
"""

# macOS: launch agents and daemons, which is where nearly everything persists.
# Apple's own bundled ones under /System are skipped — they are the baseline on
# every Mac, and listing them buries the handful that are not.
_MAC = r"""
exec 2>/dev/null
echo '#begin'
LIMIT=__LIMIT__
n=0
emit() {
  n=$((n+1))
  if [ "$n" -gt "$LIMIT" ]; then echo '#truncated'; exit 0; fi
  printf '%s|%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$5" "$6"
}
clean() { printf '%s' "$1" | tr -d '|' | tr -d '\r\n'; }
scan_dir() {
  [ -d "$1" ] || return
  for f in "$1"/*.plist; do
    [ -f "$f" ] || continue
    lbl=$(/usr/libexec/PlistBuddy -c 'Print :Label' "$f" 2>/dev/null)
    prg=$(/usr/libexec/PlistBuddy -c 'Print :Program' "$f" 2>/dev/null)
    if [ -z "$prg" ]; then
      prg=$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$f" 2>/dev/null)
    fi
    dis=$(/usr/libexec/PlistBuddy -c 'Print :Disabled' "$f" 2>/dev/null)
    on=1
    [ "$dis" = "true" ] && on=0
    emit "$2" "$(clean "${lbl:-$(basename "$f" .plist)}")" "$(clean "$prg")" "$(clean "$f")" "$3" "$on"
  done
}
for dir in /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly; do
  [ -d "$dir" ] || continue
  for f in "$dir"/*; do
    [ -f "$f" ] || continue
    emit periodic "$(clean "$(basename "$f")")" "$(clean "$f")" "$(clean "$dir")" system 1
  done
done
scan_dir /Library/LaunchDaemons launch-daemon system
scan_dir /Library/LaunchAgents launch-agent system
for home in /Users/*; do
  [ -d "$home/Library/LaunchAgents" ] || continue
  scan_dir "$home/Library/LaunchAgents" launch-agent "user:$(basename "$home")"
done
if [ -x /etc/rc.common ]; then
  emit rc-common rc.common /etc/rc.common /etc/rc.common system 1
fi
"""


# Falcon's `platform_name`, lowercased, to the script that can read that OS.
# Matched on a prefix because the field is not a closed set: "Windows", "Linux",
# "Mac" and "macOS" have all been seen in the wild.
_SCRIPTS = (("win", "win"), ("mac", "mac"), ("linux", "linux"), ("ubuntu", "linux"),
            ("rhel", "linux"), ("centos", "linux"), ("debian", "linux"),
            ("amazon", "linux"), ("suse", "linux"), ("oracle", "linux"))

# The scripts to run on each OS, in order, as (label, body).
#
# Windows is **three** scripts rather than one, and not for tidiness: a
# `runscript -Raw` command travels as one string in a REST body, and that string
# is not unbounded. The single script came to 4.8 KB, which is close enough to the
# limits quoted for RTR that a host would refuse it — and a refused script comes
# back as empty output, which is indistinguishable from a machine with nothing to
# report. Splitting also buys failure granularity: if reading the scheduled tasks
# trips over one bad task, the Run keys have already been returned.
_PASSES = {
    "win": (("machine registry", "_WIN_MACHINE_REGISTRY"),
            ("deep registry", "_WIN_DEEP_REGISTRY"),
            ("services and tasks", "_WIN_SERVICES_TASKS"),
            ("wmi subscriptions", "_WIN_WMI"),
            ("per-user", "_WIN_PER_USER")),
    "linux": (("all", "_LINUX"),),
    "mac": (("all", "_MAC"),),
}


def _minify(script):
    """Drop comment-only and blank lines.

    The comments in these scripts are worth a great deal in this file and nothing
    at all on the wire, where they are the difference between a command that fits
    and one that may not: the autorun script carries far more explanation than the
    others, and an RTR command string is not unbounded. Only lines whose first
    non-space character is `#` go — so `echo '#begin'`, which starts with `echo`,
    is untouched, and no string literal is ever cut into.
    """
    kept = [ln for ln in script.split("\n")
            if ln.strip() and not ln.lstrip().startswith("#")]
    return "\n".join(kept) + "\n"


def _script_for(platform, limit=MAX_ROWS_PER_HOST):
    """The enumeration scripts for a Falcon `platform_name`, as (label, script).

    Raises [`_UnknownOS`] rather than guessing. Guessing would mean falling
    through to the shell script, and on a Windows host that does not fail
    cleanly — it comes back empty, and that host then reads as a machine with
    **no software installed**. Which is the one wrong conclusion this module must
    never invite, so an OS we cannot name is a visible failure instead. Falcon
    also reports iOS, Android and Kubernetes nodes; none can be enumerated this
    way.
    """
    p = (platform or "").strip().lower()
    which = next((kind for prefix, kind in _SCRIPTS if p.startswith(prefix)), None)
    if which is None:
        raise _UnknownOS(platform or "(not reported)")
    bodies = globals()
    out = []
    for label, name in _PASSES[which]:
        body = bodies[name]
    # This file is checked out with CRLF, so the literals above carry \r on
    # every line. PowerShell copes; /bin/sh does not — `LIMIT=400\r` compares
    # against a value with a carriage return in it and every `done` becomes an
    # unknown command. So the script is normalised to LF whichever platform it is
    # for, rather than leaving it to how this file happens to be checked out.
        script = _minify(body.replace("__LIMIT__", str(int(limit)))).replace("\r\n", "\n")
        # The script is sent inside an RTR ```…``` block, so a backtick anywhere
        # in it — including in a comment written out of Markdown habit — closes
        # that block early and corrupts the command on the wire. It fails as a
        # script that does not run rather than as an error anybody sees, so it is
        # caught here instead.
        if "`" in script:
            bad = next(n for n, ln in enumerate(script.splitlines(), 1) if "`" in ln)
            raise AssertionError(f"backtick in {label} for {platform}, line {bad}")
        if len(script) > MAX_SCRIPT_BYTES:
            raise AssertionError(
                f"{label} for {platform} is {len(script)}B, over the "
                f"{MAX_SCRIPT_BYTES}B a single runscript may carry — split it")
        out.append((label, script))
    return out


def _parse(stdout, hostname, host_id):
    """One host's stdout into autorun rows, plus what the metadata lines said.

    Deduplicated on (source, name, command, scope): the Run family is read in
    both the native and the WOW6432Node view, and the same unit can be listed by
    two systemd paths.

    Disabled entries are kept, not dropped. A disabled autostart that has no
    business existing is still a finding — it is one command away from running —
    so `enabled` is a column rather than a filter.
    """
    seen, rows = set(), []
    flags = {"truncated": False, "error": ""}
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            if line == "#begin":
                pass  # only proves the script ran; `_rtr_one` already checked
            elif line == "#truncated":
                flags["truncated"] = True
            elif line.startswith("#err="):
                # The endpoint stayed silent and told us instead.
                flags["error"] = line[5:].strip()
            continue
        parts = [f.strip() for f in line.split("|")]
        if len(parts) < 6:
            continue
        source, name, command, location, scope, enabled = parts[:6]
        if not name and not command:
            continue
        # "user:CORP\alice" carries the account; the column shows both, and the
        # scope stays comparable across hosts.
        who = ""
        if scope.startswith("user:"):
            scope, who = "user", scope[5:]
        key = (source, name.lower(), command.lower(), scope, who)
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "host": hostname,
            "host_id": host_id,
            "source": source,
            "name": name,
            "command": command,
            "location": location,
            "scope": scope,
            "user": who,
            "enabled": enabled == "1",
        })
    rows.sort(key=lambda r: (r["source"], r["name"].lower()))
    return rows, flags


# --------------------------------------------------------------------------- #
# Scanning: one worker per host, so a finished host is usable immediately.
# --------------------------------------------------------------------------- #
def _log(line):
    """Queue a line for the dispatch thread to log. Safe from any thread."""
    _logq.put(line)


def _set(hid, **fields):
    """Update one host's job state under the lock."""
    with _lock:
        job = _jobs.get(hid)
        if job is not None:
            job.update(fields)


def _worker(hid, token, base, stop):
    """Enumerate one host. Runs on a pool thread; touches only `_jobs` (locked),
    `_logq`, and the network."""
    with _lock:
        job = _jobs.get(hid)
        if job is None:
            return
        hostname, platform = job["hostname"], job["platform"]
    if stop.is_set():
        _set(hid, state="stopped")
        return
    _set(hid, state="scanning")
    try:
        stdout = _rtr_one(hid, platform, token, base, stop)
        rows, flags = _parse(stdout, hostname, hid)
        notes = []
        if flags["truncated"]:
            notes.append(t("note.truncated", n=MAX_ROWS_PER_HOST))
        if flags["error"]:
            # The script caught something on the endpoint and reported it here
            # instead of showing it there. Surfaced as a note, not a failure: the
            # rows it did manage to send are still good.
            notes.append(flags["error"])
        if not rows and not notes:
            notes.append(t("note.empty"))
        _set(hid, state="done", autoruns=rows, notes=notes)
        _log(f"cs-autoruns: {hostname} — {len(rows)} entries")
    except _Stopped:
        _set(hid, state="stopped")
    except _UnknownOS as exc:
        _set(hid, state="skipped", error=str(exc))
        _log(f"cs-autoruns: {hostname} skipped — {exc}")
    except Exception as exc:  # noqa: BLE001
        _set(hid, state="failed", error=str(exc))
        _log(f"cs-autoruns: {hostname} failed — {exc}")


def _start(host, targets):
    """Queue `targets` and start the pool. Returns the status line.

    The token is fetched **here**, on the dispatch thread, and handed to the
    workers: asking for it from a worker would mean using the host bridge off the
    RPC thread.
    """
    if not targets:
        return t("status.none_selected")
    if _busy():
        return t("status.already_running")
    try:
        token, base = _auth(host)
    except Exception as exc:  # noqa: BLE001
        host.log(f"cs-autoruns: auth failed: {exc}")
        return str(exc)

    stop = threading.Event()
    with _lock:
        _jobs.clear()
        for target in targets:
            _jobs[target["id"]] = {
                "hostname": target.get("hostname") or target["id"],
                "platform": target.get("platform", ""),
                "state": "queued",
                "autoruns": [],
                "error": "",
                "notes": [],
            }
    pool = ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(targets)))
    _run.update(pool=pool, stop=stop, started=time.time())
    for target in targets:
        pool.submit(_worker, target["id"], token, base, stop)
    # Nothing is waited on: the pool is left running and the view polls it, so
    # the dispatch thread returns to drawing immediately.
    host.log(f"cs-autoruns: scanning {len(targets)} host(s) on "
             f"{min(MAX_WORKERS, len(targets))} thread(s)")
    return t("status.starting", n=len(targets))


def _busy():
    """Whether any host is still queued or in flight."""
    with _lock:
        return any(j["state"] in ("queued", "scanning") for j in _jobs.values())


def _drain_log(host):
    """Move whatever the workers queued into the host log. Dispatch thread only."""
    while True:
        try:
            host.log(_logq.get_nowait())
        except queue.Empty:
            return


def _tally():
    with _lock:
        states = [j["state"] for j in _jobs.values()]
        autoruns = sum(len(j["autoruns"]) for j in _jobs.values())
    return {
        "total": len(states),
        "done": states.count("done"),
        "failed": states.count("failed"),
        "stopped": states.count("stopped"),
        "skipped": states.count("skipped"),
        "running": states.count("scanning") + states.count("queued"),
        "autoruns": autoruns,
    }


def _targets_from(rows):
    return [
        {"id": h["id"], "hostname": h.get("hostname", ""),
         "platform": h.get("platform", "")}
        for h in rows
        if h.get("id")
    ]


# --------------------------------------------------------------------------- #
# Methods.
# --------------------------------------------------------------------------- #
@m.method("fetch")
def fetch(params, host):
    """Load the reachable inventory from the crowdstrike capability."""
    try:
        inv = host.call("crowdstrike", "hosts", {})
        # Only reachable hosts: RTR cannot open a session to a host that is
        # offline, so listing them as scannable would only produce failures.
        rows = inv.get("accessible", []) if isinstance(inv, dict) else []
        _hosts["rows"] = rows
        _status["msg"] = t("status.reachable", n=len(rows))
    except Exception as exc:  # noqa: BLE001
        _hosts["rows"] = None
        _status["msg"] = t("status.fetch_failed", err=exc)
        host.log(f"cs-autoruns: fetch failed: {exc}")
    return m._view_spec()


@m.method("scan_selected")
def scan_selected(params, host):
    """Start scanning the ticked hosts."""
    rows = _hosts["rows"] or []
    selected = [h for h in rows if params.get(f"sel_{h.get('id')}")]
    _status["msg"] = _start(host, _targets_from(selected))
    return m._view_spec()


@m.method("scan_all")
def scan_all(params, host):
    """Start scanning every host in the current list."""
    _status["msg"] = _start(host, _targets_from(_hosts["rows"] or []))
    return m._view_spec()


@m.method("progress")
def progress(params, host):
    """One tick of the progress loop: drain the workers' log lines, wait a beat,
    and re-render.

    The wait is the throttle. The host re-invokes an `auto` action the moment the
    view renders, so answering immediately would spin the loop as fast as the two
    processes can pass frames.
    """
    _drain_log(host)
    if _busy():
        time.sleep(POLL_SECONDS)
    t = _tally()
    if t["running"]:
        _status["msg"] = (
            f"scanning — {t['done']} of {t['total']} done, "
            f"{t['autoruns']} entries so far"
        )
    else:
        _shutdown_pool()
        parts = [f"{t['done']} host(s) scanned", f"{t['autoruns']} entries"]
        if t["failed"]:
            parts.append(f"{t['failed']} failed")
        if t["stopped"]:
            parts.append(f"{t['stopped']} stopped")
        if t["skipped"]:
            parts.append(f"{t['skipped']} unsupported")
        _status["msg"] = " · ".join(parts)
    return m._view_spec()


def _shutdown_pool():
    """Let the finished pool go. Not blocking: every worker has already left."""
    pool = _run.get("pool")
    if pool is not None:
        pool.shutdown(wait=False)
        _run["pool"] = None


@m.method("stop")
def stop(params, host):
    """Call off the scan.

    A host already in flight finishes its current HTTP call — there is no way to
    un-ask a request that is out — but nothing new is started, and anything still
    queued is marked stopped rather than left looking as though it is coming.
    """
    ev = _run.get("stop")
    if ev is not None:
        ev.set()
    with _lock:
        for job in _jobs.values():
            if job["state"] == "queued":
                job["state"] = "stopped"
    host.log("cs-autoruns: stop requested")
    _status["msg"] = t("status.stopping")
    return m._view_spec()


# --------------------------------------------------------------------------- #
# One host's autoruns, in its own tab.
# --------------------------------------------------------------------------- #
def columns():
    """Column headings, in the current language. A function rather than a
    constant, which would freeze whichever language the module was imported in."""
    return [t("col.source"), t("col.name"), t("col.command"),
            t("col.scope"), t("col.enabled"), t("col.location")]


def _cells(r):
    scope = r.get("scope", "")
    if r.get("user"):
        scope = f"{scope} · {r['user']}"
    return [r.get("source", ""), r.get("name", ""), r.get("command", ""),
            scope, t("col.yes") if r.get("enabled") else t("col.no"), r.get("location", "")]


# Entries shown in a host tab, by row id, so `about` can resolve one. Keyed
# "<host id>:<index>" rather than by index alone: several host tabs are open at
# once, and row 3 means a different entry in each.
_shown = {}

# The filter text per open host tab, so two tabs can be narrowed differently.
_query = {}


@m.method("open_host")
def open_host(params, host):
    """A finished host's autoruns, opened in a tab. The double-click target."""
    _sync_locale()
    hid = str(params.get("id", ""))
    with _lock:
        job = dict(_jobs.get(hid) or {})
    if not job:
        return Window(t("ui.col_host"), [Label(t("host.unknown"))]).to_spec()
    name = job["hostname"]
    if job["state"] != "done":
        return Window(name, [
            Label(name, style="heading"),
            Label(state_text(job["state"]), style="weak"),
            Label(job["error"], style="weak") if job["error"] else Separator(),
        ]).to_spec()

    # A filter typed in this tab arrives with the call; otherwise the one this tab
    # was last left with, so a refresh does not silently widen the list.
    if "query" in params:
        _query[hid] = params.get("query") or ""
    query = (_query.get(hid) or "").lower()

    entries = job["autoruns"]
    on, off, on_ids, off_ids = [], [], [], []
    for i, r in enumerate(entries):
        cells = _cells(r)
        if query and query not in " ".join(cells).lower():
            continue
        rid = f"{hid}:{i}"
        _shown[rid] = r
        if r["enabled"]:
            on_ids.append(rid)
            on.append(cells)
        else:
            off_ids.append(rid)
            off.append(cells)

    by_source = {}
    for r in entries:
        by_source[r["source"]] = by_source.get(r["source"], 0) + 1
    breakdown = ", ".join(f"{n} {k}" for k, n in sorted(by_source.items(),
                                                        key=lambda kv: -kv[1]))

    menu = [MenuItem(t("entry.about"), capability=CAP, method="about",
                     open_in_tab=True)]
    widgets = [
        Label(name, style="heading"),
        Label(t("host.summary", n=len(entries)), style="weak"),
    ]
    if breakdown:
        widgets.append(Label(breakdown, style="weak"))
    for note in job["notes"]:
        widgets.append(Label("! " + note, style="weak"))
    widgets.append(Row([
        Text("query", label=t("ui.search"), placeholder=t("ui.search_hint"),
             default=_query.get(hid, "")),
        # Re-opens this same tab with the filter applied; the host id rides along
        # so the button knows which host it is filtering.
        Button(t("ui.filter"), calls="open_host", args={"id": hid}),
    ]))
    if query:
        widgets.append(Label(t("ui.shown_of", shown=len(on) + len(off),
                                 total=len(entries)), style="weak"))

    widgets += [Separator(), Label(t("host.enabled", n=len(on)), style="strong")]
    widgets.append(
        Table(columns(), on, row_ids=on_ids, menu=menu, on_activate=(CAP, "about"))
        if on else Label(t("host.nothing_enabled") if not query
                         else t("ui.no_match"), style="weak"))
    # Disabled entries get their own section rather than being dropped: one that
    # has no business existing is a finding either way, and it is one command away
    # from running.
    if off or not query:
        widgets += [Separator(), Label(t("host.disabled", n=len(off)), style="strong")]
        widgets.append(
            Table(columns(), off, row_ids=off_ids, menu=menu, on_activate=(CAP, "about"))
            if off else Label(t("host.nothing_disabled"), style="weak"))
    return Window(name, widgets).to_spec()


@m.method("about")
def about(params, host):
    """One autostart entry, opened in a tab."""
    _sync_locale()
    r = _shown.get(str(params.get("id", "")))
    if not r:
        return Window(t("entry.window"), [Label(t("entry.gone"))]).to_spec()

    def field(label, value):
        return Label(f"{label}: {value}" if value else f"{label}: —")

    scope = r.get("scope", "")
    if r.get("user"):
        scope = f"{scope} ({r['user']})"
    return Window(r.get("name") or t("entry.window"), [
        Label(r.get("name") or t("entry.unnamed"), style="heading"),
        Label(t("entry.is_enabled") if r.get("enabled") else t("entry.is_disabled"),
              style="weak"),
        Separator(),
        field(t("entry.host"), r.get("host")),
        field(t("entry.command"), r.get("command")),
        field(t("entry.kind"), r.get("source")),
        field(t("entry.starts_for"), scope),
        field(t("entry.location"), r.get("location")),
        Separator(),
        field(t("entry.falcon_id"), r.get("host_id")),
    ]).to_spec()


@m.method("autoruns")
def autoruns(params, host):
    """The capability method: every scanned autostart entry as data.

    Reports the last scan rather than starting one — a scan runs across the fleet
    and takes minutes, which is not something another module should set off by
    asking a question.

    ``{"enabled": true|false}`` narrows to one side; ``{"source": "run-key"}``
    to one kind of autostart.
    """
    with _lock:
        if not _jobs:
            return {"error": "nothing scanned yet", "total": 0, "autoruns": []}
        rows = [r for j in _jobs.values() for r in j["autoruns"]]
        failed = {j["hostname"]: j["error"] for j in _jobs.values()
                  if j["state"] in ("failed", "skipped")}
        # Computed here rather than by calling `_busy()`: that takes `_lock` too,
        # and `_lock` is a plain Lock, not an RLock.
        pending = any(j["state"] in ("queued", "scanning") for j in _jobs.values())
    want = params.get("enabled")
    if want is not None:
        rows = [r for r in rows if r["enabled"] == bool(want)]
    source = (params.get("source") or "").strip().lower()
    if source:
        rows = [r for r in rows if r["source"].lower() == source]
    on = sum(1 for r in rows if r["enabled"])
    return {
        "note": "What auto-starts across CrowdStrike fleet hosts, read over RTR. "
                "Disabled entries are included and marked, not dropped — one that "
                "should not exist is a finding either way. Per-user locations come "
                "from every profile on the host, not the one RTR runs as.",
        "scanning": pending,
        "total": len(rows),
        "enabled": on,
        "disabled": len(rows) - on,
        "hosts": len({r["host_id"] for r in rows}),
        "failed_hosts": failed,
        "autoruns": rows,
    }

# --------------------------------------------------------------------------- #
# The screen.
# --------------------------------------------------------------------------- #
# What each job state says, and which `Step` icon it gets. "pending" is the idle
# dot, "loading" the spinner, "done" the check — so a failed or stopped host
# reads as finished-and-not-ok rather than as still going, which is the one thing
# it must never look like.
def state_text(state):
    """What a host's row says it is doing, in the current language."""
    return t("state." + state) if state in (
        "queued", "scanning", "done", "failed", "stopped", "skipped") else state
_STATE_ICON = {
    "queued": "pending",
    "scanning": "loading",
    "done": "done",
    "failed": "pending",
    "stopped": "pending",
    "skipped": "pending",
}


class Step:
    """A progress step: an animated spinner that morphs into a check.

    Built as a raw spec rather than imported, because the Python SDK has no `Step`
    even though the host renders one. Same for the view's `auto` below.
    """

    def __init__(self, label="", state="pending"):
        self.label, self.state = label, state

    def to_spec(self):
        return {"kind": "step", "label": self.label, "state": self.state}


def _host_lines(widgets, rows):
    """One line per host: the tick box that selects it, and — once a scan has
    touched it — the live state beside it."""
    with _lock:
        jobs = {hid: dict(j) for hid, j in _jobs.items()}
    for h in rows:
        hid = h.get("id", "")
        job = jobs.get(hid)
        line = [Checkbox(f"sel_{hid}", label=h.get("hostname", "?"))]
        if job:
            text = state_text(job["state"])
            if job["state"] == "done":
                text = t("status.items", n=len(job["autoruns"]))
            elif job["state"] == "failed" and job["error"]:
                text = t("state.failed_why", why=job["error"][:60])
            line.append(Step(label=text, state=_STATE_ICON.get(job["state"], "pending")))
        widgets.append(Row(line))
        detail = "   ·   ".join(p for p in [
            h.get("os", ""),
            f"SN {h['serial']}" if h.get("serial") else "",
            h.get("tags", ""),
        ] if p)
        if detail:
            widgets.append(Label("      " + detail, style="weak"))


def _finished_table(widgets):
    """The hosts that have finished, double-click to open one.

    Separate from the lines above because a table row is what carries a
    double-click, and because it is the natural place to be told which hosts are
    ready to look at while the rest are still running.
    """
    with _lock:
        done = [(hid, dict(j)) for hid, j in _jobs.items() if j["state"] == "done"]
    if not done:
        return
    done.sort(key=lambda kv: kv[1]["hostname"].lower())
    rows, ids = [], []
    for hid, j in done:
        on = sum(1 for r in j["autoruns"] if r["enabled"])
        rows.append([j["hostname"], str(len(j["autoruns"])), str(on),
                     str(len(j["autoruns"]) - on)])
        ids.append(hid)
    widgets += [
        Separator(),
        Label(t("ui.scanned", n=len(rows)), style="strong"),
        Table([t("ui.col_host"), t("ui2.col_entries"), t("ui2.col_enabled"),
               t("ui2.col_disabled")], rows,
              row_ids=ids, on_activate=(CAP, "open_host"),
              menu=[MenuItem(t("ui.open_host"), capability=CAP, method="open_host",
                             open_in_tab=True)]),
    ]


def _failed_table(widgets):
    """Hosts that were not read, listed rather than counted.

    An absent host is the one case where an empty result means nothing at all, so
    the operator has to know which machine to go and look at by hand. Hosts whose
    OS this module cannot read are in here too: they are not failures, but they
    are equally not answers, and leaving them out would quietly shrink the fleet.
    """
    with _lock:
        bad = [dict(j) for j in _jobs.values() if j["state"] in ("failed", "skipped")]
    if not bad:
        return
    widgets += [
        Separator(),
        Label(t("ui.not_scanned", n=len(bad)), style="strong"),
        Table([t("ui.col_host"), t("ui.col_why")], sorted([[j["hostname"], j["error"]] for j in bad])),
    ]


@m.ui
def ui():
    _sync_locale()
    widgets = [
        Label(t("ui.title"), style="heading"),
        Label(t("ui.subtitle"), style="weak"),
    ]

    rows = _hosts["rows"]
    running = _busy()
    toolbar = [Button(t("ui.fetch_hosts"), calls="fetch", primary=rows is None,
                      enabled=not running)]
    if rows:
        toolbar.append(Button(t("ui.scan_selected"), calls="scan_selected",
                              primary=True, enabled=not running))
        toolbar.append(Button(t("ui.scan_all"), calls="scan_all",
                              enabled=not running))
        # Only offered while there is something to stop, so it is never a button
        # that does nothing.
        if running:
            toolbar.append(Button(t("ui.stop"), calls="stop", danger=True))
    widgets.append(Row(toolbar))

    if _status["msg"]:
        widgets.append(Label(_status["msg"], style="weak"))

    if rows is not None:
        widgets.append(Separator())
        widgets.append(Label(t("ui.reachable", n=len(rows)), style="strong"))
        if not rows:
            widgets.append(Label(t("ui.no_reachable"), style="weak"))
        _host_lines(widgets, rows)

    _finished_table(widgets)
    _failed_table(widgets)

    spec = Window(t("ui.title"), widgets).to_spec()
    # While anything is still running, ask the host to call `progress` as soon as
    # this has drawn — that loop is what makes the spinners move and the finished
    # hosts appear one at a time. It stops being emitted the moment the work is
    # done, which is what ends the loop.
    if running:
        spec["auto"] = {"capability": CAP, "method": "progress", "args": {}}
    return spec


if __name__ == "__main__":
    m.run()
