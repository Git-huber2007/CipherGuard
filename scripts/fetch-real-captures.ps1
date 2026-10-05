# Fetch real IPsec captures for external validation (Windows PowerShell).
# The same job as fetch-real-captures.sh, for machines without a POSIX shell.
#
# These are not vendored into this repository. They belong to the Wireshark
# project and are covered by its licence, so they are downloaded on demand and
# attributed rather than redistributed here. The tests that use them skip
# cleanly when they are absent, so an offline checkout still passes.
#
#   powershell -ExecutionPolicy Bypass -File scripts\fetch-real-captures.ps1
#   python -m cipherguard verify-real

param([string]$Dest = "samples/real")

$ErrorActionPreference = "Stop"
$Base = "https://raw.githubusercontent.com/wireshark/wireshark/master/test/captures"
$Captures = @(
    "ikev2-decrypt-aes256gcm16.pcap",
    "ikev2-decrypt-aes256gcm8.pcap",
    "ikev2-decrypt-aes128ccm12.pcap",
    "ikev2-decrypt-aes192ctr.pcap",
    "ikev1-certs.pcap"
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Write-Output "Fetching real IPsec captures into $Dest/"
Write-Output "Source: Wireshark project test suite"
Write-Output ""

$got = 0
foreach ($name in $Captures) {
    $target = Join-Path $Dest $name
    if (Test-Path $target) {
        Write-Output "  have $name"
        $got++
        continue
    }
    try {
        Invoke-WebRequest -UseBasicParsing -Uri "$Base/$name" -OutFile $target
        Write-Output "  got  $name ($((Get-Item $target).Length) bytes)"
        $got++
    } catch {
        if (Test-Path $target) { Remove-Item -LiteralPath $target }
        Write-Output "  MISS $name (no network, or the upstream path has moved)"
    }
}

Write-Output ""
Write-Output "$got capture(s) available. Validate with:"
Write-Output "    python -m cipherguard verify-real"
