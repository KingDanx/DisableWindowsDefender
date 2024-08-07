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

function Enable-ProtectAllNetworkConnections {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Profile = "StandardProfile"  # Options: "StandardProfile", "DomainProfile", "PublicProfile"
    )

    # Define the registry path based on the profile
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$Profile"

    # Ensure the path exists
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    # Set the "EnableFirewall" value to 1 (Enable)
    Set-ItemProperty -Path $regPath -Name "EnableFirewall" -Value 1 -Force

    # Set the "DoNotAllowExceptions" value to 1 (Protect all network connections)
    Set-ItemProperty -Path $regPath -Name "DoNotAllowExceptions" -Value 1 -Force

    Write-Output "The 'Protect all network connections' setting has been enabled for the $Profile."
}

# Example usage:
# Enable-ProtectAllNetworkConnections -Profile "DomainProfile"
# Enable-ProtectAllNetworkConnections -Profile "StandardProfile"
# Enable-ProtectAllNetworkConnections -Profile "PublicProfile"



function Reboot-Safe-Mode {
    Give-Folder-Access -ItemListPath "C:\ProgramData\Microsoft\Windows Defender\Platform"
    Give-Folder-Access -ItemListPath "C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator"
    Remove-ACL "C:\ProgramData\Microsoft\Windows Defender\Platform" -Recurse -Verbose
    Remove-ACL "C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator" -Recurse -Verbose
    Enable-ProtectAllNetworkConnections -Profile "DomainProfile"
    Enable-ProtectAllNetworkConnections -Profile "StandardProfile"
    Enable-ProtectAllNetworkConnections -Profile "PublicProfile"
    Enable-Windows-Defender

    Write-Output "`r`nWindow Security has been restored`nPress enter to reboot.`n"
    Pause
    cmd.exe /c "shutdown -r -t 0"
}

Reboot-Safe-Mode