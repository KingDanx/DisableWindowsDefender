function Give-Folder-Access {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ItemListPath
    )
    
    $currentPCUser = [Environment]::UserName.ToUpper()

    $Account = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList "$currnetPCUser`\Administrators";

    # Get a list of folders and files
    $ItemList = Get-ChildItem -Path $ItemListPath -Recurse;
    
    # Iterate over files/folders
    foreach ($Item in $ItemList) {
        $Acl = $null; # Reset the $Acl variable to $null
        $Acl = Get-Acl -Path $Item.FullName; # Get the ACL from the item
        $Acl.SetOwner($Account); # Update the in-memory ACL
        Set-Acl -Path $Item.FullName -AclObject $Acl; # Set the updated ACL on the target item
    }
}

Function Remove-ACL {    
    [CmdletBinding(SupportsShouldProcess = $True)]
    Param(
        [parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [String[]]$Folder,
        [Switch]$Recurse
    )

    Process {

        foreach ($f in $Folder) {

            if ($Recurse) { $Folders = $(Get-ChildItem $f -Recurse -Directory).FullName } else { $Folders = $f }

            if ($Folders -ne $null) {

                $Folders | ForEach-Object {

                    # Remove inheritance
                    $acl = Get-Acl $_
                    $acl.SetAccessRuleProtection($true, $true)
                    Set-Acl $_ $acl

                    # Remove ACL
                    $acl = Get-Acl $_
                    try {
                        $acl.Access | % { $acl.RemoveAccessRule($_) } | Out-Null
                    }
                    catch {
                        Write-Output "Access modified to Administator account."
                    }
                    

                    # Add local admin
                    $permission = "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
                    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
                    $acl.SetAccessRule($rule)

                    Set-Acl $_ $acl

                    Write-Verbose "Remove-HCacl: Inheritance disabled and permissions removed from $_"
                }
            }
            else {
                Write-Verbose "Remove-HCacl: No subfolders found for $f"
            }
        }
    }
}

function Disable-Windows-Defender {
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\WinDefend" -Name "Start" -Value 4 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\wscsvc" -Name "Start" -Value 4 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\Sense" -Name "Start" -Value 4 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\WdBoot" -Name "Start" -Value 4 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\WdFilter" -Name "Start" -Value 4 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\WdNisDrv" -Name "Start" -Value 4 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\WdNisSvc" -Name "Start" -Value 4 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\SecurityHealthService" -Name "Start" -Value 4 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\mpssvc" -Name "Start" -Value 4 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\UsoSvc" -Name "Start" -Value 4 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\wuauserv" -Name "Start" -Value 4 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\WaaSMedicSvc" -Name "Start" -Value 4 -force | out-null
        
        #Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet\Services\WinDefend" -Name "Start" -Value 4 -force | out-null
        #Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet\ServicesSense" -Name "Start" -Value 4 -force | out-null
        #Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet\Services\WdBoot" -Name "Start" -Value 4 -force | out-null
        #Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet\Services\WdFilter" -Name "Start" -Value 4 -force | out-null
        #Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet\Services\WdNisDrv" -Name "Start" -Value 4 -force | out-null
        #Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet\Services\WdNisSvc" -Name "Start" -Value 4 -force | out-null
        #Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet\Services\SecurityHealthService" -Name "Start" -Value 4 -force | out-null
        Write-Output "`r`nWindows Defender disabled.`n"
    }
    catch {
        Write-Output "error"
    }
}
function Disable-WindowsTask {
    param (
        [string]$taskName
    )
    
    try {
        Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop

        Write-Output "`r`nWindows Task '$taskName' disabled and deleted.`n"
    }
    catch {
        Write-Output "`r`nFailed to disable or delete Windows Task '$taskName': $_.`n"
    }
}

function Disable-All-Tasks {
    Disable-WindowsTask -taskName "Reboot_AC"
    Disable-WindowsTask -taskName "Reboot_Battery"
    Disable-WindowsTask -taskName "Report policies"
    Disable-WindowsTask -taskName "Schedule Maintenance Work"
    Disable-WindowsTask -taskName "Schedule Scan"
    Disable-WindowsTask -taskName "Schedule Scan Static Task"
    Disable-WindowsTask -taskName "Schedule Wake To Work"
    Disable-WindowsTask -taskName "Schedule Work"
    Disable-WindowsTask -taskName "UpdateModelTask"
    Disable-WindowsTask -taskName "USO_UxBroker"
    Disable-WindowsTask -taskName "RunUpdateNotificationMgr"
    Disable-WindowsTask -taskName "Refresh Group Policy Cache"
    Disable-WindowsTask -taskName "Scheduled Start"
    Disable-WindowsTask -taskName "Windows Defender Cache Maintenance"
    Disable-WindowsTask -taskName "Windows Defender Cleanup"
    Disable-WindowsTask -taskName "Windows Defender Scheduled Scan"
    Disable-WindowsTask -taskName "Windows Defender Verification"
    Disable-WindowsTask -taskName "XblGameSaveTask"
    Disable-WindowsTask -taskName "Consolidator"
    Disable-WindowsTask -taskName "UsbCeip"

    Remove-TaskFolder -FolderPath "C:\Windows\System32\Tasks\Microsoft\Windows\WindowsUpdate"
    Remove-TaskFolder -FolderPath "C:\Windows\System32\Tasks\Microsoft\XblGameSave"
    Remove-TaskFolder -FolderPath "C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator"
    Remove-TaskFolder -FolderPath "C:\Windows\System32\Tasks\Microsoft\Windows\UNP"
    Remove-TaskFolder -FolderPath "C:\Windows\System32\Tasks\Microsoft\Windows\Windows Defender"
    Remove-TaskFolder -FolderPath "C:\Windows\System32\Tasks\Microsoft\Windows\Customer Experience Improvement Program"
}

function Remove-TaskFolder {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FolderPath
    )
    
    # Ensure the folder exists
    if (-Not (Test-Path -Path $FolderPath -PathType Container)) {
        Write-Error "The specified folder does not exist: $FolderPath"
        return
    }

    # Attempt to remove the folder and all its contents
    try {
        Remove-Item -Path $FolderPath -Force -Recurse
        Write-Output "The folder '$FolderPath' and all its contents have been removed."
    }
    catch {
        Write-Error "Failed to remove the folder: $($_.Exception.Message)"
    }
}


function Reboot-Safe-Mode {
    $owner = Get-Acl "C:\ProgramData\Microsoft\Windows Defender\Platform"
    $bootState = (gwmi win32_computersystem -Property BootupState).BootupState
    if ((gwmi win32_computersystem -Property BootupState).BootupState -eq 'Normal Boot') {
        #$owner.Owner -eq "NT AUTHORITY\SYSTEM" -and ----> May add this back later
        cmd.exe /c "bcdedit /set {default} safeboot minimal "
        Write-Output "`r`nSafe Mode has been set.`n`nPress enter to reboot. Run this script again once the computer has been reset.`n"
        Pause
        Restart-Computer
    }
    elseif ( (gwmi win32_computersystem -Property BootupState).BootupState -eq "Fail-safe boot") {
        cmd.exe /c "bcdedit /deletevalue {default} safeboot "
        Write-Output "Normal Boot has been restored.`n`nPress enter to reboot. Run this script again once the computer has been reset."
        TAKEOWN /F "C:\ProgramData\Microsoft\Windows Defender\Platform" /A /R /D Y
        Give-Folder-Access -ItemListPath "C:\ProgramData\Microsoft\Windows Defender\Platform"
        Give-Folder-Access -ItemListPath "C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator"
        Remove-ACL "C:\ProgramData\Microsoft\Windows Defender\Platform" -Recurse -Verbose
        Remove-ACL "C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator" -Recurse -Verbose
        Disable-Windows-Defender
        Disable-All-Tasks

        Write-Output "`r`nNormal Boot has been set.`nPress enter to reboot. Run this script again once the computer has been reset.`n"
        Pause
        cmd.exe /c "shutdown -r -t 0"
    }
    else {
        Write-Output "Folder owned by Administrator"
        Pause
    }
}

Reboot-Safe-Mode