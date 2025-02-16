
Write-Host ("[+] Decargando informacion desde loldrivers.io ...")
$web_client = New-Object System.Net.WebClient
try {
    $jsonString = $web_client.DownloadString("https://www.loldrivers.io/api/drivers.json")
} finally {
    $web_client.Dispose()
}
$computerName = $env:COMPUTERNAME
$loldrivers = ($jsonString -replace '"INIT"','"init"') | ConvertFrom-Json
$driverOutput = driverquery /FO list /v
Write-Host ("[+] Inspeccionando drives cargados en el equipo '{0}' ..." -f $computerName)
$drivers = @()
$driver = @{}
foreach ($line in $driverOutput) {
    if ($line -match '^\s*$') {
        if ($driver.Count -gt 0) {
            $drivers += [PSCustomObject]$driver
            $driver = @{}
        }
    } elseif ($line -match '^\s*([^:]+):\s*(.*)\s*$') {
        $driver[$matches[1].Trim()] = $matches[2].Trim()
    }
}

if ($driver.Count -gt 0) {
    $drivers += [PSCustomObject]$driver
}

Write-Host ("[+] Comparando {0} drivers cargados en '{1}' con la base de datos de loldrivers.io ..." -f $drivers.Count,$computerName )
$processedDrivers = @{}

foreach ($lol in $loldrivers.KnownVulnerableSamples) {
    $matchingDriver = $drivers | Where-Object { $_."Module Name" -eq $lol.Filename }

    if ($matchingDriver) {
        $driverPath = $matchingDriver.path
        $driverPath = $driverPath.Replace('\??\', '')
        if ($processedDrivers[$driverPath]) {
            continue
        }
        $processedDrivers[$driverPath] = $true
        if ($driverPath) {
            if (Test-Path $driverPath) {
                $hash = Get-FileHash -Path $driverPath
                if ($lol.Sha256 -eq $hash.Hash) {
                    Write-Host ("`t`tDriver {0} vulnerable | Hash(SHA256) {1}| {2} " -f $lol.Filename, $lol.Sha256,$driverPath) -ForegroundColor yellow
                }
            } else {
                Write-Host ("`t`tArchivo no encontrado: {0}" -f $driverPath) -ForegroundColor Yellow
            }
        } else {
            Write-Host ("`t`tNo se encontro ninguna ruta para: {0}" -f $lol.Filename) -ForegroundColor Yellow
        }
    }
}
Write-Host ("[+] Fin ...")
