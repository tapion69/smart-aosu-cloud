#requires -version 5.1
<#
Lecture ADB sans root de traces cpDeviceId de l'application AOSU officielle.
Aucune commande camera, aucun journal ni identifiant conserve sur disque.
#>
[CmdletBinding()]
param([switch]$SelfTest,[ValidateRange(1000,50000)][int]$MaxLines=20000)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Find-Adb {
    $paths=New-Object 'System.Collections.Generic.List[string]'
    $cmd=Get-Command adb.exe -CommandType Application -ErrorAction SilentlyContinue
    if($null -ne $cmd -and $cmd.Source){[void]$paths.Add($cmd.Source)}
    foreach($home in @($env:LOCALAPPDATA,$env:ANDROID_HOME,$env:ANDROID_SDK_ROOT)){
        if([string]::IsNullOrWhiteSpace($home)){continue}
        if($home -eq $env:LOCALAPPDATA){
            [void]$paths.Add((Join-Path $home 'Android\Sdk\platform-tools\adb.exe'))
        }else{
            [void]$paths.Add((Join-Path $home 'platform-tools\adb.exe'))
        }
    }
    foreach($path in $paths){
        if(Test-Path -LiteralPath $path -PathType Leaf){return $path}
    }
    return $null
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

Write-Host 'SMART AOSU - LECTURE ADB SANS ROOT - AUCUN LOG BRUT ENREGISTRE'
$adb=Find-Adb
if([string]::IsNullOrWhiteSpace($adb)){
    Write-Host 'ETAT : ADB_INTROUVABLE - installer Android SDK Platform-Tools'
    exit 2
}
try{
    $rows=@(& $adb devices 2>$null)
    $devices=@($rows|Where-Object{$_ -match '^[^\s]+\s+device\s*$'})
    if($LASTEXITCODE -ne 0 -or $devices.Count -ne 1){
        Write-Host 'ETAT : TELEPHONE_ABSENT_OU_MULTIPLE - autoriser le debogage USB'
        exit 3
    }
    $pidText=[string]((& $adb shell pidof -s com.glazero.android 2>$null)-join ' ')
    if($pidText -notmatch '^\s*\d+\s*$'){
        Write-Host 'ETAT : APPLICATION_AOSU_NON_OUVERTE - ouvrir AOSU officiel'
        exit 4
    }
    Write-Host 'Dans AOSU officiel, ouvrir une fois le direct de la C9C.'
    [void](Read-Host 'Revenir sur le PC et appuyer sur Entree')
    $pidText=[string]((& $adb shell pidof -s com.glazero.android 2>$null)-join ' ')
    if($pidText -notmatch '^\s*\d+\s*$'){
        Write-Host 'ETAT : PROCESSUS_AOSU_ARRETE'
        exit 5
    }
    # Lecture du seul PID AOSU, ni effacement de logcat ni ecriture sur disque.
    $lines=@(& $adb logcat -d -t $MaxLines --pid=$($pidText.Trim()) -v brief 2>$null)
    if($LASTEXITCODE -ne 0){
        Write-Host 'ETAT : LOGCAT_NON_AUTORISE_OU_INCOMPATIBLE'
        exit 6
    }
    $result=New-AnonymousReport -Lines $lines
    $lines=$null
    Write-Host '=== RAPPORT ANONYMISE ==='
    $result | ConvertTo-Json -Depth 2
    Write-Host '=== FIN DU RAPPORT ==='
    Write-Host 'Un marqueur cpDeviceId ne prouve pas la liaison a la C9C.'
}catch{
    # Ne jamais exposer une erreur externe pouvant contenir des donnees.
    Write-Host 'ETAT : ERREUR_LECTURE_ADB_SANS_DETAILS'
    exit 7
}
