param(
    [string]$ArchivePath,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'wireguard-nt.json') -Raw | ConvertFrom-Json
$destination = Join-Path $PSScriptRoot 'dependencies/wireguard-nt'

function Get-Sha256 {
    param([string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $stream = [IO.File]::OpenRead($resolved)
        try {
            return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '')
        } finally { $stream.Dispose() }
    } finally { $algorithm.Dispose() }
}

function Test-Inputs {
    foreach ($entry in $manifest.files.PSObject.Properties) {
        $file = Join-Path $destination $entry.Name
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return $false }
        if ((Get-Sha256 -Path $file) -ine $entry.Value) { return $false }
    }
    return $true
}

if (Test-Inputs) { return }
if ($CheckOnly) { throw 'WireGuardNT inputs missing or modified. Run restore-wireguard-nt.ps1 before building.' }

$temporary = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N') + '.zip')
try {
    if (-not $ArchivePath) {
        Add-Type -AssemblyName System.Net.Http
        $handler = [Net.Http.HttpClientHandler]::new()
        $handler.AllowAutoRedirect = $false
        $client = [Net.Http.HttpClient]::new($handler)
        try {
            $response = $client.GetAsync($manifest.url).GetAwaiter().GetResult()
            try {
                if ($response.StatusCode -ne [Net.HttpStatusCode]::OK) {
                    throw "WireGuardNT download failed (redirects are not followed): $($response.StatusCode)"
                }
                [IO.File]::WriteAllBytes($temporary, $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult())
            } finally { $response.Dispose() }
        } finally { $client.Dispose(); $handler.Dispose() }
        $ArchivePath = $temporary
    }
    if ((Get-Sha256 -Path $ArchivePath) -ine $manifest.sha256) {
        throw 'Official WireGuardNT archive SHA-256 mismatch; nothing will be extracted.'
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $ArchivePath).Path)
    try {
        foreach ($entry in $manifest.files.PSObject.Properties) {
            $member = $zip.GetEntry("wireguard-nt/$($entry.Name)")
            if (-not $member) { throw "Missing pinned WireGuardNT input: $($entry.Name)" }
            $file = Join-Path $destination $entry.Name
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($file)) | Out-Null
            [IO.Compression.ZipFileExtensions]::ExtractToFile($member, $file, $true)
        }
    } finally { $zip.Dispose() }
    if (-not (Test-Inputs)) { throw 'WireGuardNT extracted input SHA-256 mismatch.' }
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
}
