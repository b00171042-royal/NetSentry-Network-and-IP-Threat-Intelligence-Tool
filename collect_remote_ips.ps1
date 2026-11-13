# Output file names
param(
    [string]$OutJson = "ps_remote_ips.json",
    [string]$OutCsv  = "ps_remote_ips.csv"
)

# Basic Host INfo
$hostInfo = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    UserName     = $env:USERNAME
    TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
}

# Active TCP connections, ignores certain remote addresses (empty or only local)
$connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object {
        $_.RemoteAddress -and
        $_.RemoteAddress -ne "0.0.0.0" -and
        $_.RemoteAddress -ne "::"
    } |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess


# Enriches connections by giving them all process names since all have a pid but not a name
# Failures are labelled as unknown

$enrichedConnections = foreach ($c in $connections) {

    $processName = "UNKNOWN"

    try {
        $processName = (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName
    }
    catch {
        # Some system processes cannot be accessed
        $processName = "UNKNOWN"
    }

    # Create a clean custom object for output
    [pscustomobject]@{
        RemoteIP    = $c.RemoteAddress
        RemotePort  = $c.RemotePort
        LocalIP     = $c.LocalAddress
        LocalPort   = $c.LocalPort
        PID         = $c.OwningProcess
        ProcessName = $processName
    }
}

#Output for JSON/CSV so it's easy to read in python 
$outputObject = [pscustomobject]@{
    Host        = $hostInfo
    Connections = $enrichedConnections
}

$outputObject |
    ConvertTo-Json -Depth 4 |
    Out-File -Encoding UTF8 $OutJson

$enrichedConnections |
    Export-Csv -NoTypeInformation -Encoding UTF8 $OutCsv

#Summary of the console to know everything is smooth
Write-Host "Collection complete."
Write-Host "JSON written to:" $OutJson
Write-Host "CSV written to:" $OutCsv
Write-Host "Unique remote IPs found:" (
    ($enrichedConnections.RemoteIP | Sort-Object -Unique).Count
)
