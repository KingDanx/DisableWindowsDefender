function Give-Folder-Access {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ItemListPath
    )
    
    # Define the SYSTEM account
    $Account = [System.Security.Principal.NTAccount]::new("NT AUTHORITY\SYSTEM")

    # Define the access rule to grant Full Control
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Account, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
    
    # Get a list of folders and files
    $ItemList = Get-ChildItem -Path $ItemListPath -Recurse
    
    # Iterate over files/folders
    foreach ($Item in $ItemList) {
        # Get the ACL from the item
        $Acl = Get-Acl -Path $Item.FullName
        
        # Add the new access rule
        $Acl.AddAccessRule($AccessRule)
        
        # Set the updated ACL on the target item
        Set-Acl -Path $Item.FullName -AclObject $Acl
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

            if ($Recurse) { 
                $Folders = $(Get-ChildItem $f -Recurse -Directory).FullName 
            }
            else { 
                $Folders = $f 
            }

            if ($Folders -ne $null) {

                $Folders | ForEach-Object {

                    # Remove inheritance
                    $acl = Get-Acl $_
                    $acl.SetAccessRuleProtection($true, $true)
                    Set-Acl $_ $acl

                    # Remove existing ACLs
                    $acl = Get-Acl $_
                    try {
                        $acl.Access | % { $acl.RemoveAccessRule($_) } | Out-Null
                    }
                    catch {
                        Write-Output "Access modified to Administrator account."
                    }
                    
                    # Add access for SYSTEM account
                    $systemPermission = "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
                    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule $systemPermission
                    $acl.SetAccessRule($systemRule)

                    # Add local admin access
                    $adminPermission = "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
                    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule $adminPermission
                    $acl.SetAccessRule($adminRule)

                    Set-Acl $_ $acl

                    Write-Verbose "Remove-ACL: Inheritance disabled, permissions removed, and access granted to SYSTEM and Administrators for $_"
                }
            }
            else {
                Write-Verbose "Remove-ACL: No subfolders found for $f"
            }
        }
    }
}

function Enable-Windows-Defender {
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\WinDefend" -Name "Start" -Value 2 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\wscsvc" -Name "Start" -Value 2 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\Sense" -Name "Start" -Value 2 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\WdBoot" -Name "Start" -Value 2 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\WdFilter" -Name "Start" -Value 2 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\WdNisDrv" -Name "Start" -Value 2 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\WdNisSvc" -Name "Start" -Value 2 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\SecurityHealthService" -Name "Start" -Value 2 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\mpssvc" -Name "Start" -Value 2 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\UsoSvc" -Name "Start" -Value 2 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\wuauserv" -Name "Start" -Value 2 -force | out-null
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\WaaSMedicSvc" -Name "Start" -Value 2 -force | out-null
        
        #Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet\Services\WinDefend" -Name "Start" -Value 4 -force | out-null
        #Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet\ServicesSense" -Name "Start" -Value 4 -force | out-null
        #Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet\Services\WdBoot" -Name "Start" -Value 4 -force | out-null
        #Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet\Services\WdFilter" -Name "Start" -Value 4 -force | out-null
        #Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet\Services\WdNisDrv" -Name "Start" -Value 4 -force | out-null
        #Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet\Services\WdNisSvc" -Name "Start" -Value 4 -force | out-null
        #Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet\Services\SecurityHealthService" -Name "Start" -Value 4 -force | out-null
        Write-Output "`r`nWindows Defender enabled.`n"
    }
    catch {
        Write-Output "error"
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
        Enable-Windows-Defender

        Write-Output "`r`nNormal Boot has been set.`nPress enter to reboot. Run this script again once the computer has been reset.`n"
        Pause
        cmd.exe /c "shutdown -r -t 0"
    }
}

Reboot-Safe-Mode