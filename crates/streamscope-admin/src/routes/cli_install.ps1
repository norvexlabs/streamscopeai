# Streamscope CLI installer for Windows (Windows PowerShell 5.1 or PowerShell 7).
# Downloads ssai.exe, verifies its sha256, installs it to
# $env:STREAMSCOPE_INSTALL_DIR (default: %LOCALAPPDATA%\Programs\ssai) and puts
# that folder on the user's PATH. Run:  irm <gateway>/api/v1/cli/install.ps1 | iex
#
# The gateway's certificate is Windows' to trust: a gateway with a private
# certificate authority has its root installed in Windows first (the same
# trust `irm` itself needs to fetch this script). Proxies are Windows'
# settings, as for any download.
#
# Every value the gateway fills in sits in a single-quoted string: it stays a
# value, never code. The whole script runs in one script block, so `iex`
# leaves no variable behind in the caller's session.
& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $Origin = '__ORIGIN__'
    $Version = '__VERSION__'
    $WantSha = '__SHA256__'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    if (-not [Environment]::Is64BitOperatingSystem) {
        throw 'ssai: unsupported platform (supported: Windows x86_64)'
    }
    # Absolute — against PowerShell's own location, which the process's may
    # differ from: the folder goes on the user's PATH, where a relative one
    # would name a different folder from every directory.
    $Dir = if ($env:STREAMSCOPE_INSTALL_DIR) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($env:STREAMSCOPE_INSTALL_DIR) } else { Join-Path $env:LOCALAPPDATA 'Programs\ssai' }

    # Whether a failure is the gateway's certificate not being trusted here.
    function Test-TrustFailure($e) {
        for ($x = $e; $x; $x = $x.InnerException) {
            if ($x -is [Security.Authentication.AuthenticationException]) { return $true }
            if ($x -is [Net.WebException] -and $x.Status -eq [Net.WebExceptionStatus]::TrustFailure) { return $true }
        }
        return $false
    }

    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    $tmp = Join-Path $Dir ".ssai.$PID.tmp"
    $exe = Join-Path $Dir 'ssai.exe'
    try {
        Write-Host "Downloading ssai v$Version (windows-x86_64) from $Origin ..."
        # A proxy that asks for Windows sign-in gets the user's own credentials.
        if ([Net.WebRequest]::DefaultWebProxy) { [Net.WebRequest]::DefaultWebProxy.Credentials = [Net.CredentialCache]::DefaultNetworkCredentials }
        try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 600 -Uri "$Origin/api/v1/cli/download/windows-x86_64" -OutFile $tmp }
        catch {
            if (Test-TrustFailure $_.Exception) {
                throw "ssai: Windows does not trust the gateway's TLS certificate. A gateway with a private certificate authority needs its root installed first: your IT department, or certmgr.msc (Trusted Root Certification Authorities) with the root from $Origin/api/v1/cli/ca, after checking its fingerprint with the gateway's operator. Then re-run."
            }
            throw
        }
        $gotSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $tmp).Hash.ToLowerInvariant()
        if ($gotSha -ne $WantSha) {
            throw "ssai: sha256 mismatch (got $gotSha, want $WantSha) - aborting"
        }
        # A running ssai.exe can be renamed but not replaced: it steps aside as
        # ssai.old.exe — ssai.old-2.exe … ssai.old-9.exe while earlier ones
        # still run (the names `ssai update` uses) — which a later start of ssai
        # removes, and comes back if the new one cannot take its place.
        $steppedAside = $false
        if (Test-Path -LiteralPath $exe) {
            $old = @('ssai.old.exe') + (2..9 | ForEach-Object { "ssai.old-$_.exe" }) | ForEach-Object { Join-Path $Dir $_ } |
                Where-Object { Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $_; -not (Test-Path -LiteralPath $_) } |
                Select-Object -First 1
            if (-not $old) { throw 'ssai: nine earlier copies of ssai.exe are still running - close them, then re-run.' }
            Move-Item -LiteralPath $exe -Destination $old
            $steppedAside = $true
        }
        try { Move-Item -LiteralPath $tmp -Destination $exe }
        catch {
            if ($steppedAside) { Move-Item -LiteralPath $old -Destination $exe }
            throw
        }
    }
    finally { Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $tmp }

    # $Version is the GATEWAY's version; report what the binary says about
    # itself, and name a disagreement (a stale artifact on the gateway).
    $got = ''
    try { $got = ((& $exe --version) -split '\s+')[-1] } catch { }
    if (-not $got) {
        Write-Host "Installed $exe (gateway advertised v$Version; the binary reported no version)"
    } elseif ($got -ne $Version) {
        Write-Warning "this gateway advertises v$Version but served a v$got binary. Its CLI artifact is out of date; logging in may fail against it. Tell the gateway operator."
        Write-Host "Installed $exe (v$got)"
    } else {
        Write-Host "Installed $exe (v$Version)"
    }

    # Whether the PATH value $PathValue holds the folder $Folder, however it is
    # spelled there (`%VAR%` entries, a trailing `\`, any case).
    function Test-OnPath([string]$PathValue, [string]$Folder) {
        $norm = { param($p) [Environment]::ExpandEnvironmentVariables($p).TrimEnd('\').ToLowerInvariant() }
        $want = & $norm $Folder
        return [bool](($PathValue -split ';') | Where-Object { $_ -and (& $norm $_) -eq $want })
    }

    # The user PATH is read and written as stored (REG_EXPAND_SZ, `%VAR%`
    # entries unexpanded): [Environment]::SetEnvironmentVariable would flatten it.
    $envKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try {
        $userPath = [string]$envKey.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if (-not (Test-OnPath $userPath $Dir)) {
            $envKey.SetValue('Path', ((@($userPath, $Dir) | Where-Object { $_ }) -join ';'), [Microsoft.Win32.RegistryValueKind]::ExpandString)
            # Tells running programs (Explorer) the environment changed: setting
            # and clearing a variable broadcasts that, as the system dialog does.
            [Environment]::SetEnvironmentVariable('SSAI_INSTALL_REFRESH', '1', 'User')
            [Environment]::SetEnvironmentVariable('SSAI_INSTALL_REFRESH', $null, 'User')
            Write-Host "Added $Dir to your PATH (new terminals see it)."
        }
    }
    finally { $envKey.Close() }
    if (-not (Test-OnPath $env:Path $Dir)) { $env:Path = "$env:Path;$Dir" }
    Write-Host 'Next: ssai login <your portal URL>'
}
