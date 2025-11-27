param(
    [switch]$RunAll,
    [switch]$ShowStatus,
    [switch]$UpdateOnly,
    [switch]$QuickScan,
    [switch]$FullScan,
    [string]$CustomScanPath = "",
    [switch]$OfflineScan,
    [switch]$EnableRealtime,
    [switch]$DisableRealtime,
    [switch]$AddExclusionPath,
    [switch]$AddExclusionProcess,
    [switch]$AddExclusionExtension,
    [switch]$RemoveExclusionPath,
    [switch]$RemoveExclusionProcess,
    [switch]$RemoveExclusionExtension,
    [switch]$ListExclusions,
    [string]$ExclusionPath = "",
    [string]$ExclusionProcess = "",
    [string]$ExclusionExtension = "",
    [switch]$RemoveThreat,
    [string]$ThreatID = ""
)

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Warning "Algumas operações requerem privilégios de administrador. Reexecute o script como Administrador se precisar dessas ações."
    }
    return $isAdmin
}

function Run-IfAdmin {
    param(
        [scriptblock]$Action,
        [string]$ActionName = "ação"
    )
    if (Assert-Admin) {
        try {
            & $Action
        } catch {
            Write-Error "Erro ao executar $ActionName: $_"
        }
    } else {
        Write-Warning "Pulando $ActionName porque não há privilégios de administrador."
    }
}

# Se nenhum parâmetro foi passado, executar RunAll por padrão
if ($PSBoundParameters.Count -eq 0) {
    $RunAll = $true
}

Write-Output "=== Manage-Defender script iniciado: $(Get-Date -Format u) ==="

if ($ShowStatus -or $RunAll) {
    Write-Output "`n-- Status atual do Microsoft Defender --"
    try {
        Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, AntivirusSignatureVersion, NISEnabled, RealTimeProtectionEnabled, QuickScanTime | Format-List
    } catch {
        Write-Warning "Não foi possível obter o status do Defender: $_"
    }
}

if ($ListExclusions -or $RunAll) {
    Write-Output "`n-- Exclusões atuais (Get-MpPreference) --"
    try {
        $prefs = Get-MpPreference
        Write-Output "ExclusionPath:"
        $prefs.ExclusionPath | ForEach-Object { Write-Output "  $_" }
        Write-Output "ExclusionProcess:"
        $prefs.ExclusionProcess | ForEach-Object { Write-Output "  $_" }
        Write-Output "ExclusionExtension:"
        $prefs.ExclusionExtension | ForEach-Object { Write-Output "  $_" }
    } catch {
        Write-Warning "Falha ao listar exclusões: $_"
    }
}

if ($UpdateOnly) {
    Write-Output "`n-- Atualizando definições do Defender (Update-MpSignature) --"
    Run-IfAdmin -Action { Update-MpSignature } -ActionName "Update-MpSignature"
    return
}

if ($RunAll -or $UpdateOnly) {
    if ($RunAll -or $UpdateOnly) {
        Write-Output "`n-- Atualizando definições do Defender (Update-MpSignature) --"
        Run-IfAdmin -Action { Update-MpSignature } -ActionName "Update-MpSignature"
    }
}

if ($QuickScan -or $RunAll) {
    Write-Output "`n-- Iniciando QuickScan --"
    try {
        Start-MpScan -ScanType QuickScan
        Write-Output "QuickScan iniciado."
    } catch {
        Write-Warning "Falha ao iniciar QuickScan: $_"
    }
}

if ($FullScan -or $RunAll) {
    Write-Output "`n-- Iniciando FullScan --"
    try {
        Start-MpScan -ScanType FullScan
        Write-Output "FullScan iniciado."
    } catch {
        Write-Warning "Falha ao iniciar FullScan: $_"
    }
}

if ($CustomScanPath -ne "" -or ($RunAll -and $CustomScanPath -ne "")) {
    if ($CustomScanPath -ne "") {
        Write-Output "`n-- Iniciando CustomScan no caminho: $CustomScanPath --"
        try {
            Start-MpScan -ScanType CustomScan -ScanPath $CustomScanPath
            Write-Output "CustomScan iniciado em $CustomScanPath."
        } catch {
            Write-Warning "Falha ao iniciar CustomScan: $_"
        }
    }
}

if ($OfflineScan -or $RunAll) {
    Write-Output "`n-- Solicitando OfflineScan --"
    Run-IfAdmin -Action { Start-MpScan -ScanType OfflineScan } -ActionName "Start-MpScan OfflineScan"
    Write-Output "OfflineScan foi solicitado (o sistema pode reiniciar para concluir)."
}

# Realtime control
if ($EnableRealtime) {
    Write-Output "`n-- Habilitando proteção em tempo real --"
    Run-IfAdmin -Action { 
        Set-MpPreference -DisableRealtimeMonitoring $false
        Write-Output "Defender: Realtime habilitado (Set-MpPreference -DisableRealtimeMonitoring $false)."
    } -ActionName "Set-MpPreference (Enable Realtime)"
}

if ($DisableRealtime) {
    Write-Warning "Desabilitar a proteção em tempo real reduz a proteção do sistema. Só faça isso se souber o que está fazendo."
    Write-Output "`n-- Desabilitando proteção em tempo real --"
    Run-IfAdmin -Action { 
        Set-MpPreference -DisableRealtimeMonitoring $true
        Write-Output "Defender: Realtime desabilitado (Set-MpPreference -DisableRealtimeMonitoring $true)."
    } -ActionName "Set-MpPreference (Disable Realtime)"
}

# Gerenciar exclusões (sem excluir arquivos do Windows)
if ($AddExclusionPath -and -not [string]::IsNullOrWhiteSpace($ExclusionPath)) {
    Write-Output "`n-- Adicionando exclusão de caminho: $ExclusionPath --"
    Run-IfAdmin -Action { Add-MpPreference -ExclusionPath $using:ExclusionPath } -ActionName "Add-MpPreference -ExclusionPath"
}

if ($AddExclusionProcess -and -not [string]::IsNullOrWhiteSpace($ExclusionProcess)) {
    Write-Output "`n-- Adicionando exclusão de processo: $ExclusionProcess --"
    Run-IfAdmin -Action { Add-MpPreference -ExclusionProcess $using:ExclusionProcess } -ActionName "Add-MpPreference -ExclusionProcess"
}

if ($AddExclusionExtension -and -not [string]::IsNullOrWhiteSpace($ExclusionExtension)) {
    Write-Output "`n-- Adicionando exclusão de extensão: $ExclusionExtension --"
    Run-IfAdmin -Action { Add-MpPreference -ExclusionExtension $using:ExclusionExtension } -ActionName "Add-MpPreference -ExclusionExtension"
}

if ($RemoveExclusionPath -and -not [string]::IsNullOrWhiteSpace($ExclusionPath)) {
    Write-Output "`n-- Removendo exclusão de caminho: $ExclusionPath --"
    Run-IfAdmin -Action { Remove-MpPreference -ExclusionPath $using:ExclusionPath } -ActionName "Remove-MpPreference -ExclusionPath"
}

if ($RemoveExclusionProcess -and -not [string]::IsNullOrWhiteSpace($ExclusionProcess)) {
    Write-Output "`n-- Removendo exclusão de processo: $ExclusionProcess --"
    Run-IfAdmin -Action { Remove-MpPreference -ExclusionProcess $using:ExclusionProcess } -ActionName "Remove-MpPreference -ExclusionProcess"
}

if ($RemoveExclusionExtension -and -not [string]::IsNullOrWhiteSpace($ExclusionExtension)) {
    Write-Output "`n-- Removendo exclusão de extensão: $ExclusionExtension --"
    Run-IfAdmin -Action { Remove-MpPreference -ExclusionExtension $using:ExclusionExtension } -ActionName "Remove-MpPreference -ExclusionExtension"
}

# Remoção de ameaça (se solicitado) - mantive, mas é opcional e só executa se pedir explicitamente
if ($RemoveThreat) {
    if ([string]::IsNullOrWhiteSpace($ThreatID)) {
        Write-Warning "RemoveThreat foi solicitado, mas ThreatID não foi informado. Use -ThreatID '<id>' para remover."
    } else {
        Write-Output "`n-- Tentando remover ameaça: $ThreatID --"
        Run-IfAdmin -Action { Remove-MpThreat -ThreatID $using:ThreatID } -ActionName "Remove-MpThreat"
    }
}

Write-Output "`n=== Manage-Defender script finalizado: $(Get-Date -Format u) ==="