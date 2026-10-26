# ASIX endpoint agent installer for Windows. Made by ASIX for ONE tenant (docs/endpoints.md, task E5): it installs the endpoint agent on THIS machine, enrols it with the
# tenant's endpoint manager and starts it. Windows PowerShell 5.1 or newer, run as administrator. This file is plain ASCII on purpose.
#
# Usage (elevated PowerShell; the script is not signed, so start it like this):
#   powershell -ExecutionPolicy Bypass -File .\asix-endpoint-install.ps1 -Check     # look only: system, manager reachable, package reachable; changes nothing
#   powershell -ExecutionPolicy Bypass -File .\asix-endpoint-install.ps1 [-Name NAME] [-PasswordFile FILE] [-MsiPath FILE] [-MsiSha256 HASH] [-Upgrade] [-ReEnroll]
#
#   -Name NAME         how this machine is listed in ASIX (default: its computer name; letters, digits . _ -, 2 to 128 characters).
#   -PasswordFile F    read the enrolment password from the first line of F. Without it the script uses $env:ASIX_ENROLL_PASSWORD, then a password that was put
#                      into this script when it was made, then asks. The password is never put on a command line and is not left on this machine.
#   -MsiPath FILE      use this agent package instead of downloading it (a machine with no internet access). It is checked like a downloaded one.
#   -MsiSha256 HASH    refuse the package unless its SHA-256 is HASH (64 hex characters). The script always prints the hash and who signed the package.
#   -Upgrade           allow replacing an installed agent of a different version.
#   -ReEnroll          enrol again although this machine already has an agent key (the old key is kept as client.keys.before-asix).
#
# What it changes, in order (each step is safe to repeat; run it again if it stops half way):
#   1. checks (administrator, PowerShell version, the manager answers on its agent and enrolment ports, the package can be fetched)
#   2. downloads the agent package at exactly the version below, refuses it unless Windows says its signature is valid, installs it
#   3. enrols the agent with agent-auth (the password goes through a temporary file that only SYSTEM and administrators can read, removed again)
#   4. names the service "ASIX Endpoint Security agent" (the service and the package keep their upstream names), makes it start automatically, starts it
#   5. waits until the agent says it is connected to the manager
# It does not open any firewall: this machine must reach @MANAGER@ on 1514/tcp (events) and 1515/tcp (enrolment).
[CmdletBinding(PositionalBinding = $false)]
param(
  [switch]$Check,
  [string]$Name = '',
  [string]$PasswordFile = '',
  [string]$MsiPath = '',
  [string]$MsiSha256 = '',
  [switch]$Upgrade,
  [switch]$ReEnroll,
  [Parameter(ValueFromRemainingArguments = $true)] [string[]]$Rest
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$MANAGER = '@MANAGER@'; $GROUP = '@GROUP@'; $WANT = '@VERSION@'
$EmbeddedPassword = '__ASIX_ENROLL_PASSWORD__'; $Placeholder = '__ASIX_ENROLL_' + 'PASSWORD__'   # a password put in by the portal is base64 of its UTF-8 bytes

function Say($m) { Write-Host $m }
function Err($m) { [Console]::Error.WriteLine($m) }
function Die($m, $code = 1) { Err $m; exit $code }

if ($Rest -and $Rest.Count -gt 0) { Die ('Unknown argument: ' + ($Rest -join ' ')) 2 }

# Names and checks that only need the arguments (exit 2 = a mistake in how the script was started).
if (-not $Name) {
  $Name = ([string]$env:COMPUTERNAME).ToLower() -replace '[^a-z0-9._-]', '-'
  $Name = $Name.TrimStart('-', '.', '_')
  if ($Name.Length -gt 128) { $Name = $Name.Substring(0, 128) }
  if ($Name.Length -lt 2) { $Name = 'endpoint' }
}
if ($Name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$') { Die '-Name must be 2 to 128 characters: letters, digits, dot, underscore, hyphen (it must start with a letter or digit).' 2 }
if ($MsiSha256) { $MsiSha256 = ($MsiSha256 -replace '\s', '').ToUpper(); if ($MsiSha256 -notmatch '^[0-9A-F]{64}$') { Die '-MsiSha256 must be 64 hex characters.' 2 } }

# Where things are. The environment variables exist for the tests; on a real machine the defaults are right.
$pf86 = ${env:ProgramFiles(x86)}
if ($env:ASIX_AGENT_DIR) { $OSSEC = $env:ASIX_AGENT_DIR }
elseif ($pf86) { $OSSEC = Join-Path $pf86 'ossec-agent' }
else { $OSSEC = Join-Path $env:ProgramFiles 'ossec-agent' }
$PORT_EVENTS = if ($env:ASIX_AGENT_PORT) { [int]$env:ASIX_AGENT_PORT } else { 1514 }
$PORT_ENROL = if ($env:ASIX_ENROL_PORT) { [int]$env:ASIX_ENROL_PORT } else { 1515 }
$WAIT_S = if ($env:ASIX_AGENT_WAIT_S) { [int]$env:ASIX_AGENT_WAIT_S } else { 60 }
$SERVICE = 'WazuhSvc'
$MSI_URL = 'https://packages.wazuh.com/4.x/windows/wazuh-agent-' + $WANT + '.msi'
$WantVer = $WANT -replace '-\d+$', ''
$KEYS = Join-Path $OSSEC 'client.keys'
$LOG = Join-Path $OSSEC 'ossec.log'

function Test-Admin {
  if ($env:ASIX_TEST_ADMIN) { return ($env:ASIX_TEST_ADMIN -eq '1') }
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Test-Tcp($h, $p) {
  $c = New-Object Net.Sockets.TcpClient
  try { $a = $c.BeginConnect($h, [int]$p, $null, $null); if (-not $a.AsyncWaitHandle.WaitOne(5000, $false)) { return $false }; $c.EndConnect($a); return $true }
  catch { return $false } finally { $c.Close() }
}
function Get-InstalledVersion {
  $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
  $e = Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'Wazuh Agent*' } | Select-Object -First 1
  if (-not $e) { return '' }
  if ([string]$e.DisplayVersion -match '^(\d+\.\d+\.\d+)') { return $Matches[1] }
  return 'unknown'
}
function Get-LogLines { if (Test-Path -LiteralPath $LOG) { return @(Get-Content -LiteralPath $LOG -ErrorAction SilentlyContinue) } return @() }
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

# The enrolment password: -PasswordFile, then the environment, then one put into this script, then (when someone is at the keyboard) a question.
$PASSWORD = ''
if ($PasswordFile) {
  if (-not (Test-Path -LiteralPath $PasswordFile)) { Die ('Cannot read ' + $PasswordFile + '.') }
  $first = Get-Content -LiteralPath $PasswordFile -TotalCount 1
  $PASSWORD = ([string]$first).TrimEnd("`r", "`n")
} elseif ($env:ASIX_ENROLL_PASSWORD) { $PASSWORD = $env:ASIX_ENROLL_PASSWORD }
elseif ($EmbeddedPassword -ne $Placeholder) {
  try { $PASSWORD = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($EmbeddedPassword)) } catch { Die 'The password inside this script is damaged: make the script again.' }
}
Remove-Item Env:\ASIX_ENROLL_PASSWORD -ErrorAction SilentlyContinue

$script:Problems = 0; $script:Warnings = 0
function Problem($m) { Err ('   PROBLEM: ' + $m); $script:Problems++ }
function Warn($m) { Err ('   warning: ' + $m); $script:Warnings++ }

Say '== 1. Checks =='
if (-not (Test-Admin)) { Die 'Run this in an elevated PowerShell (right-click, Run as administrator).' }
if ($PSVersionTable.PSVersion.Major -lt 5) { Problem ('PowerShell ' + $PSVersionTable.PSVersion + ' is too old: this installer needs Windows PowerShell 5.1 or newer.') }
$Installed = Get-InstalledVersion
$InstalledText = if ($Installed) { $Installed } else { 'none' }
Say ('   installed agent: ' + $InstalledText + '; wanted: ' + $WantVer + '; this machine will be listed as: ' + $Name + ' (group ' + $GROUP + ')')
if ($Installed -and $Installed -ne $WantVer -and -not $Upgrade) { Problem ('Agent ' + $Installed + ' is installed, not ' + $WantVer + '. Run again with -Upgrade to replace it on purpose.') }
foreach ($p in @($PORT_EVENTS, $PORT_ENROL)) {
  if (Test-Tcp $MANAGER $p) { Say ('   ' + $MANAGER + ':' + $p + '/tcp answers') }
  else { Problem ('cannot reach ' + $MANAGER + ':' + $p + '/tcp: check the network and the firewall between this machine and the manager.') }
}
if ($MsiPath) {
  if (-not (Test-Path -LiteralPath $MsiPath)) { Problem ('the package ' + $MsiPath + ' does not exist.') }
} elseif ($Installed -ne $WantVer) {
  try { Invoke-WebRequest -Uri $MSI_URL -Method Head -UseBasicParsing -TimeoutSec 15 | Out-Null }
  catch { Problem ('cannot reach the agent package (' + $MSI_URL + '): check DNS, the proxy and the firewall, or download it elsewhere and use -MsiPath.') }
}
$Enrolled = (Test-Path -LiteralPath $KEYS) -and ((Get-Item -LiteralPath $KEYS).Length -gt 0)
$NeedPw = -not ($Enrolled -and -not $ReEnroll)
if ($NeedPw -and -not $PASSWORD) {
  if ($Check) { Warn 'no enrolment password was given: a real run will ask for it (or use -PasswordFile).' }
  elseif ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
    $sec = Read-Host -AsSecureString '   Enrolment password'
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { $PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
  }
  if (-not $Check -and -not $PASSWORD) { Problem 'no enrolment password: give -PasswordFile FILE, or set $env:ASIX_ENROLL_PASSWORD, or run this where it can ask.' }
}
if ($script:Problems -gt 0) { Err ([string]$script:Problems + ' problem(s). Nothing was changed.'); exit 1 }
if ($Check) { Say ('Checks passed (' + $script:Warnings + ' warning(s)). Nothing was changed.'); exit 0 }

$Downloaded = ''
try {
  Say '== 2. Agent package =='
  if ($Installed -eq $WantVer) {
    Say ('   agent ' + $WantVer + ' is already installed: kept')
  } else {
    $Msi = $MsiPath
    if (-not $Msi) {
      $Downloaded = Join-Path ([IO.Path]::GetTempPath()) ('asix-agent-' + [guid]::NewGuid().ToString('N') + '.msi')
      try { Invoke-WebRequest -Uri $MSI_URL -OutFile $Downloaded -UseBasicParsing -TimeoutSec 300 } catch { Die ('Could not download the agent package from ' + $MSI_URL + '.') }
      $Msi = $Downloaded
    }
    $hash = (Get-FileHash -LiteralPath $Msi -Algorithm SHA256).Hash.ToUpper()
    Say ('   package SHA-256: ' + $hash)
    if ($MsiSha256 -and $hash -ne $MsiSha256) { Die 'The package hash is not the one you gave with -MsiSha256. Nothing was installed.' }
    $sig = Get-AuthenticodeSignature -LiteralPath $Msi
    if ([string]$sig.Status -ne 'Valid') { Die ('Windows does not accept the package signature (' + $sig.Status + '). Nothing was installed.') }
    Say ('   signed by: ' + $sig.SignerCertificate.Subject)
    Say '   compare the hash with documentation.wazuh.com (Installation guide, Wazuh agent) before you rely on it.'
    $MsiLog = Join-Path ([IO.Path]::GetTempPath()) 'asix-agent-install.log'
    # The enrolment password is NOT passed here: it would show on the command line and in the installer log. Step 3 enrols with it.
    $msiArgs = '/i "' + $Msi + '" /q /norestart /l*v "' + $MsiLog + '" WAZUH_MANAGER="' + $MANAGER + '" WAZUH_AGENT_GROUP="' + $GROUP + '" WAZUH_AGENT_NAME="' + $Name + '"'
    $r = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru
    if ($r.ExitCode -ne 0 -and $r.ExitCode -ne 3010) { Die ('The installer (msiexec) stopped with code ' + $r.ExitCode + '. Its log: ' + $MsiLog) }
    Say '   installed'
  }
  if (-not (Test-Path -LiteralPath $OSSEC)) { Die ('The agent is installed but ' + $OSSEC + ' is missing.') }

  Say '== 3. Enrolment =='
  $Enrolled = (Test-Path -LiteralPath $KEYS) -and ((Get-Item -LiteralPath $KEYS).Length -gt 0)
  if (-not $Enrolled -or $ReEnroll) {
    if (-not $PASSWORD) { Die 'The agent has no key and there is no enrolment password to get one with.' }
    if (Get-Service -Name $SERVICE -ErrorAction SilentlyContinue) { Stop-Service -Name $SERVICE -Force -ErrorAction SilentlyContinue }
    if ($Enrolled) { Copy-Item -LiteralPath $KEYS -Destination ($KEYS + '.before-asix') -Force; Set-Content -LiteralPath $KEYS -Value '' -NoNewline }
    $passFile = Join-Path $OSSEC 'authd.pass'
    try {
      [IO.File]::WriteAllText($passFile, $PASSWORD + "`n", (New-Object Text.UTF8Encoding($false)))
      & icacls.exe $passFile /inheritance:r /grant:r 'SYSTEM:(F)' 'Administrators:(F)' | Out-Null
      $a = Start-Process -FilePath (Join-Path $OSSEC 'agent-auth.exe') -ArgumentList ('-m "' + $MANAGER + '" -p ' + $PORT_ENROL + ' -G "' + $GROUP + '" -A "' + $Name + '"') -Wait -PassThru -NoNewWindow
      if ($a.ExitCode -ne 0) { Die ('Enrolment failed. Is the password right, does the group "' + $GROUP + '" exist on the manager (a group other than default must be created there first), and is there room for another agent? Run this script again after fixing it.') }
    } finally { Remove-Item -LiteralPath $passFile -Force -ErrorAction SilentlyContinue }
    Say ('   enrolled as ' + $Name)
  } else {
    Say '   this machine already has an agent key: kept (use -ReEnroll to enrol again)'
  }

  Say '== 4. Service =='
  if (-not (Get-Service -Name $SERVICE -ErrorAction SilentlyContinue)) { Die ('The service ' + $SERVICE + ' does not exist: the package did not install it.') }
  Set-Service -Name $SERVICE -DisplayName 'ASIX Endpoint Security agent' -StartupType Automatic
  $StartLine = (Get-LogLines).Count
  Restart-Service -Name $SERVICE -Force

  Say '== 5. Connection =='
  $ok = $false
  for ($i = 0; $i -lt $WAIT_S; $i++) {
    $new = @(Get-LogLines | Select-Object -Skip $StartLine)
    if ($new -match 'Connected to the server') { $ok = $true; break }
    Start-Sleep -Seconds 1
  }
  if ($ok) { Say ('Done: this machine is connected to the endpoint manager as ' + $Name + '. It shows in ASIX, Endpoints, Agents.'); exit 0 }
  Err ('The agent is installed and enrolled but did not say it is connected within ' + $WAIT_S + ' seconds.')
  $bad = @(Get-LogLines | Where-Object { $_ -match 'ERROR|WARNING' } | Select-Object -Last 5)
  if ($bad.Count -gt 0) { Err ('Last problems in ' + $LOG + ':'); foreach ($l in $bad) { Err $l } }
  Err ('Check that 1514/tcp is open from here to ' + $MANAGER + ', then: Get-Service ' + $SERVICE)
  exit 3
} finally {
  if ($Downloaded) { Remove-Item -LiteralPath $Downloaded -Force -ErrorAction SilentlyContinue }
}
