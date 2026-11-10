#requires -version 5.1
<#
Lecture ADB sans root de traces cpDeviceId de l'application AOSU officielle.
Aucune commande camera, aucun journal ni identifiant conserve sur disque.
#>
[CmdletBinding()]
param([switch]$SelfTest,[switch]$AutoRead,[string]$AdbPath,
      [ValidateRange(1000,50000)][int]$MaxLines=20000)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Find-Adb {
    $paths=New-Object 'System.Collections.Generic.List[string]'
    $cmd=Get-Command adb.exe -CommandType Application -ErrorAction SilentlyContinue
    if($null -ne $cmd -and $cmd.Source){[void]$paths.Add($cmd.Source)}
    # Never use $home: PowerShell resolves it as read-only $HOME.
    # Distinct roots also avoid misclassifying Android SDK paths.
    if(-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)){
        [void]$paths.Add((Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'))
    }
    foreach($sdkDirectory in @($env:ANDROID_HOME,$env:ANDROID_SDK_ROOT)){
        if([string]::IsNullOrWhiteSpace($sdkDirectory)){continue}
        [void]$paths.Add((Join-Path $sdkDirectory 'platform-tools\adb.exe'))
    }
    foreach($path in $paths){
        if(Test-Path -LiteralPath $path -PathType Leaf){return $path}
    }
    return $null
}


function Invoke-AdbRead {
    param([string]$Executable,[string[]]$Parameters)
    # Powershell 5.1 treats some native stderr messages as errors when
    # ErrorActionPreference='Stop' (ADB daemon startup is a known case).
    # Suppress stderr; never expose raw ADB output or IDs.
    $previous=$ErrorActionPreference
    try {
        $ErrorActionPreference='Continue'
        $outputLines=@(& $Executable @Parameters 2>$null)
        $status=[int]$LASTEXITCODE
        return [pscustomobject]@{ Code=$status; Lines=@($outputLines) }
    } finally {
        $ErrorActionPreference=$previous
    }
}

function New-AnonymousReport {
    param([AllowEmptyCollection()][string[]]$Lines)
    $markers=[ordered]@{
        chargement_liste_aosu='loadDeviceInfoList load gz device success'
        chargement_liste_tuya='loadDeviceInfoList load ty device success'
        erreur_liste_tuya='loadDeviceInfoList load ty device error'
        rapprochement_cache='cpData setMemoryCache deviceIdTy2GzMap size:'
        recherche_reference_cp='ensureDeviceListForTargetDevice targetCpDeviceId='
        recherche_reference_cp_bis='ensureDeviceListForTargetDevice find targetCpDeviceId='
        correspondance_aosu_non_trouvee='mergeDeviceInfo gz device not found!  cpDeviceId:'
        reference_cp_nulle='setMemoryCache  cpDeviceId is null deviceId:'
    }
    $observed=@{}
    foreach($key in $markers.Keys){$observed[$key]=$false}
    $found=$false
    $possibleValue=$false
    foreach($line in $Lines){
        if([string]::IsNullOrEmpty($line)){continue}
        foreach($key in $markers.Keys){
            if($line.IndexOf($markers[$key],[StringComparison]::OrdinalIgnoreCase) -ge 0){
                $observed[$key]=$true
            }
        }
        if($line.IndexOf('cpDeviceId',[StringComparison]::OrdinalIgnoreCase) -ge 0){
            $found=$true
            # Valeur seulement en RAM, jamais affichee.
            if($line -match '(?i)(?:targetCpDeviceId|cpDeviceId)\s*[:=]\s*([^\s,;]{1,256})'){
                $candidate=[string]$Matches[1]
                if($candidate -notmatch '^(null|none|nil|undefined|0|absent|empty)$'){
                    $possibleValue=$true
                }
                $candidate=$null
            }
        }
    }
    $report=[ordered]@{
        diagnostic='aosu_android_cp_adb_sans_root_v1'
        etat='lecture_terminee'
        journal_aosu_lisible=($Lines.Count -gt 0)
        marqueur_cp_trouve=$found
        valeur_cp_potentielle_dans_journal=$possibleValue
        identite_c9c_tuya_prouvee=$false
        valeurs_privees_retournees=$false
        journaux_enregistres=$false
        actions_camera_par_outil=0
    }
    foreach($key in $markers.Keys){$report[$key]=$observed[$key]}
    return [pscustomobject]$report
}

if($SelfTest){
    # Regression: execute the real Windows ADB path discovery, even when
    # adb.exe is not installed. Earlier tests never exercised Find-Adb.
    $originalUserHome=[string]$HOME
    [void](Find-Adb)
    if([string]$HOME -cne $originalUserHome){
        throw 'ECHEC_TEST_VARIABLE_HOME'
    }
    $sample=@(
        'I/AOSU : loadDeviceInfoList load gz device success deviceList=PRIVATE_SN'
        'I/AOSU : loadDeviceInfoList load ty device success'
        'I/AOSU : cpData setMemoryCache deviceIdTy2GzMap size:1'
        'W/AOSU : ensureDeviceListForTargetDevice targetCpDeviceId=PRIVATE_CP'
        'W/AOSU : mergeDeviceInfo gz device not found!  cpDeviceId:PRIVATE_CP token=PRIVATE_TOKEN'
    )
    $result=New-AnonymousReport -Lines $sample
    $text=$result|ConvertTo-Json -Compress
    if(-not $result.valeur_cp_potentielle_dans_journal -or
        -not $result.rapprochement_cache -or
        -not $result.chargement_liste_aosu -or
        -not $result.chargement_liste_tuya -or
        $result.identite_c9c_tuya_prouvee -or
        $text.Contains('PRIVATE_CP') -or
        $text.Contains('PRIVATE_TOKEN') -or
        $text.Contains('PRIVATE_SN')){throw 'ECHEC_TEST_CONFIDENTIALITE'}
    $empty=New-AnonymousReport -Lines @('I/AOSU unrelated','W/AOSU cpDeviceId:null')
    if($empty.valeur_cp_potentielle_dans_journal -or $empty.identite_c9c_tuya_prouvee){
        throw 'ECHEC_TEST_ABSENCE_REFERENCE'
    }
    Write-Output 'SELFTEST_OK'
    exit 0
}

Write-Host 'SMART AOSU - LECTURE ADB SANS ROOT - CORRECTIF 1.2'
Write-Host 'Aucun log brut ni identifiant affiche ou enregistre.'
$step='recherche_adb'
try{
    if(-not [string]::IsNullOrWhiteSpace($AdbPath)){
        if(-not (Test-Path -LiteralPath $AdbPath -PathType Leaf)){
            Write-Host 'ETAT : CHEMIN_ADB_INVALIDE'
            exit 2
        }
        $adb=$AdbPath
    }else{
        $adb=Find-Adb
    }
    if([string]::IsNullOrWhiteSpace($adb)){
        Write-Host 'ETAT : ADB_INTROUVABLE'
        exit 2
    }
    $step='liste_telephones'
    $response=Invoke-AdbRead -Executable $adb -Parameters @('devices')
    if($response.Code -ne 0){
        Write-Host 'ETAT : ADB_DEVICES_ECHEC'
        exit 3
    }
    $devices=@($response.Lines|Where-Object{$_ -match '^\S+\s+device\s*$'})
    if($devices.Count -ne 1){
        Write-Host 'ETAT : TELEPHONE_ABSENT_NON_AUTORISE_OU_MULTIPLE'
        Write-Host 'Verifier USB, debogage et autorisation ADB.'
        exit 3
    }
    $step='recherche_application'
    $response=Invoke-AdbRead -Executable $adb -Parameters @('shell','pidof','-s','com.glazero.android')
    $pidText=[string]($response.Lines -join ' ')
    if($response.Code -ne 0 -or $pidText -notmatch '^\s*\d+\s*$'){
        Write-Host 'ETAT : APPLICATION_AOSU_NON_TROUVEE'
        exit 4
    }
    Write-Host 'ETAT : ADB_ET_APPLICATION_RECONNUS'
    if(-not $AutoRead){
        Write-Host 'Ouvrir la C9C une fois dans AOSU officiel sur le telephone.'
        [void](Read-Host 'Appuyer sur Entree sur le PC quand termine')
    }
    $step='verification_application'
    $response=Invoke-AdbRead -Executable $adb -Parameters @('shell','pidof','-s','com.glazero.android')
    $pidText=[string]($response.Lines -join ' ')
    if($response.Code -ne 0 -or $pidText -notmatch '^\s*\d+\s*$'){
        Write-Host 'ETAT : APPLICATION_AOSU_ARRETEE'
        exit 5
    }
    $step='lecture_logcat'
    $pidArg='--pid='+$pidText.Trim()
    $response=Invoke-AdbRead -Executable $adb -Parameters @('logcat','-d','-t',[string]$MaxLines,$pidArg,'-v','brief')
    if($response.Code -ne 0){
        Write-Host 'ETAT : LOGCAT_REFUSE_OU_OPTION_NON_SUPPORTEE'
        exit 6
    }
    $step='analyse_anonyme'
    $report=New-AnonymousReport -Lines $response.Lines
    $response=$null
    Write-Host '=== RAPPORT ANONYMISE ==='
    $report|ConvertTo-Json -Depth 3
    Write-Host '=== FIN DU RAPPORT ==='
    Write-Host 'Un marqueur ne prouve pas la liaison a la C9C.'
    exit 0
}catch{
    # Only a predefined phase is exposed. Raw exception messages could
    # include serials, tokens, paths or logcat lines; never display them.
    Write-Host ('ETAT : ECHEC_INTERNE_ETAPE_'+$step.ToUpperInvariant())
    exit 7
}
