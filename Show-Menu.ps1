$xml = [xml](Get-Content "C:\Scripts\Show-Menu\CONFIG.XML")

# Dynamic variables from XML
$xml.Values.ChildNodes | ForEach-Object {
    $Name = $_.Name
    $Value = $_.InnerText
    New-Variable -Name $Name -Value $Value 
}

function New-Menu {
    param (
        [string]$title = "Menu", # Menu Title
        [string[]]$options, # Menu Options
        [int]$defaultIndex = 1       # Default option index (1-based)
    )

    $title = " $title "

    # Calculate the longest option length
    $longestOption = ($options | Sort-Object -Property Length -Descending | Select-Object -First 1).Length
    $barLength = [math]::Max($longestOption, $title.Length) + 5 

    # Center the title in the top bar
    $paddingTotal = $barLength - $title.Length
    $paddingLeft = [math]::Floor($paddingTotal / 2)
    $paddingRight = $paddingTotal - $paddingLeft
    $topbar = "╔" + ("═" * $paddingLeft) + $title + ("═" * $paddingRight) + "╗"

    # Bottom border
    $bottom = "╚" + ("═" * ($barLength)) + "╝"

    # Display the menu
    Write-Host $topbar
    for ($i = 0; $i -lt $options.Length; $i++) {
        $number = "[$($i + 1)]"
        $option = "$number $($options[$i])"
        $padding = $barLength - $option.Length # - 1
        $location = (' ' * $padding) + "║"

        if (($i + 1) -eq $defaultIndex) {
            Write-Host -NoNewline "║"
            Write-Host -ForegroundColor Yellow $option -NoNewline
            Write-Host $location
        }
        else {
            Write-Host -NoNewline "║"
            Write-Host $option -NoNewline
            Write-Host $location
        }
    }
    Write-Host $bottom
}

function Show-SearchMenu {

    param (
        [string]$title = "SearchBy"
    )

    while ($true) {
        Clear-Host

        New-Menu -title "Search Menu" @("Disabled", "LockedOut", "PasswordExpired", "Back") -defaultIndex 4
        $value = Read-Host "Make a selection, (default is `"4`")"
        switch ($value) {
            '1' {
                # Get all disabled AD users in the specified OU
                $disabledUsers = Get-ADUser -Filter { Enabled -eq $false } -SearchBase $OUStandaard -Properties LastLogonDate

                # Iterate through disabled users and fetch replication metadata
                $metadata = foreach ($user in $disabledUsers) {
                    $metadataEntry = Get-ADReplicationAttributeMetadata -Object $user.DistinguishedName -Server (Get-ADDomainController).HostName
                    $disableMetadata = $metadataEntry | Where-Object { $_.AttributeName -eq "userAccountControl" }
    
                    [PSCustomObject]@{
                        UserName           = $user.SamAccountName
                        LastDisabledTime   = $disableMetadata.LastOriginatingChangeTime
                        LastLogonTimestamp = $user.LastLogonDate
                        DistinguishedName  = $user.DistinguishedName
                    }
                }

                # Sort the results by LastDisabledTime in descending order and display
                $metadata | Sort-Object LastDisabledTime -Descending | Format-Table -Wrap

                Pause
            }
            '2' {
                $lockedAccounts = Search-ADAccount -LockedOut | Select-Object Name, ObjectClass
                $lockedAccounts | Format-Table -AutoSize
                Pause
            }
            '3' {
                $passExpiredAccounts = Search-ADAccount -PasswordExpired | Select-Object Name, ObjectClass
                $passExpiredAccounts | Format-Table -AutoSize
                Pause
            }
            '4' { return }
            Default { return }
        }
    }
}

function Show-SubMenuSearchGroup {
    
    while ($true) {
        New-Menu -title "Sub Menu" -options @("Search Group", "Back") -defaultIndex 2
        $value = Read-Host "Enter your choice, (default is `"2`")"
        switch ($value) {
            "1" {
                Search-ADGroup
            }
            # Exit Option
            "2" { return }
            # Default
            Default {
                return
            }
        }
    }
}

function Search-ADGroup {

    $searchTerm = ""

    while ($searchTerm -eq "") {
        $searchTerm = Read-Host "Enter group to search, or `"*`" for all."
        $filter = "Name -like '*$searchTerm*'"
        if ($searchTerm -eq "*") {
            Get-ADGroup -Filter * | Format-Table Name
            Pause
        }
        elseif ($searchTerm -eq "") {
            Write-Host -ForegroundColor Red "Please try again, input was empty."
        }
        else {
            Get-ADGroup -Filter $filter -Properties Name, Description | Select-Object Name, Description | Format-Table -Wrap
            Pause
        }
    }
}

function Reset-Password {
    $number = 10..100 | Get-Random
    $string = "$($pwdString)$($number)$($pwdStringEnd)"
    Write-Host "`nTijdelijk wachtwoord is: $($string)"
    Set-ADAccountPassword -Identity $selectedUser.SamAccountName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $string -Force) -Confirm
    try {
        Invoke-Command -ComputerName "VMADCONNECT-P1" -ConfigurationName "JEA_ADConnect" -ScriptBlock { Start-ADSyncSyncCycle -PolicyType Delta }
    }
    catch {
        Write-Error $_
    }
    Pause
}
function Search-User {
    $userSearch = Read-Host "Vul naam van de user in, of `"*`" voor iedereen (default is `"1`")"
    $searchTerm = "*$userSearch*"
    $filter = "Name -like '$searchTerm' -or SamAccountName -like '$searchTerm' -or UserPrincipalName -like '$searchTerm'"

    if ($userSearch -eq "1" -or $userSearch -eq "") {
        main
    }

    try {
        if ($userSearch -eq "*") {
            $results = Get-ADUser -Filter *
        }
        else {
            $results = @(Get-ADUser -Filter $filter -Properties * | Select-Object Name, SamAccountName, UserPrincipalName)
        }
        if ($results) {
            # Clear-Host
            Write-Host "Search Results:`n"
            $i = 1
            $results | ForEach-Object {
                Write-Host "[$i]"
                Write-Host ('═' * 50)
                Write-Host "Name           : $($_.Name)"
                Write-Host "SAMAccountName : $($_.SamAccountName)"
                Write-Host ('═' * 50)
                $i++
            }
        }
        else {
            Write-Host "Geen gebruiker's gevonden, probeer opnieuw."
            Search-User
        }

        $selectedIndex = ""
        while ($selectedIndex -eq "" -or $selectedIndex -notmatch '^\d+$' -or [int]$selectedIndex -lt 1 -or [int]$selectedIndex -gt $results.Count) {
            $selectedIndex = Read-Host "`nEnter the number of the user you want more details about, or (enter) to return."
            
            if ($selectedIndex -eq "") {
                Clear-Host
                Show-SubMenuSearchUser
            }
            elseif ($selectedIndex -notmatch '^\d+$') {
                Write-Host "Invalid input. Please enter a valid number."
            }
            elseif ([int]$selectedIndex -lt 1 -or [int]$selectedIndex -gt $results.Count) {
                Write-Host "Invalid selection. Please select a number between 1 and $($results.Count)."
            }
        }
        $selectedIndex = [int]$selectedIndex

        $selectedUser = $results[$selectedIndex - 1]

        while ($true) {
            Show-UserDetails $selectedUser.SamAccountName
            New-Menu -options @("Reset Password", "Get AD Groups", "Unlock Account", "Enable Account", "Disable Account", "Add AD Groups", "Remove AD Groups", "Back") -defaultIndex 8
            $value = Read-Host "Make a selection, (default is `"8`")"
            switch ($value) {
                '1' {
                    try {
                        Reset-Password
                    }
                    catch {
                        Write-Host "`nErrorMessage: $_."
                    }
                    # Pause
                }
                '2' { Get-ADGroupsOfUser }
                '3' { Unlock-ADAccount -Identity $selectedUser.SamAccountName }
                '4' { Enable-ADAccount -Identity $selectedUser.SamAccountName }
                '5' { Disable-ADAccount -Identity $selectedUser.SamAccountName }
                '6' {
                    Get-ADGroup -Filter * -Properties Name, Description | `
                        Select-Object Name, Description | Out-GridView -PassThru -Title "Add AD Groups - multiple select possible (ctrl+leftMouseClick) or (ctrl+A) for all" | `
                        ForEach-Object { Add-ADGroupMember -Identity $_.Name -Members $selectedUser.SamAccountName -Confirm } 
                }
                '7' {
                    Get-ADUser -Identity $selectedUser.SamAccountName -Properties MemberOf | Select-Object -ExpandProperty MemberOf | `
                        ForEach-Object { Get-ADGroup $_ -Properties Name, Description } | Select-Object Name, Description | `
                        Out-GridView -PassThru -Title "Remove AD Groups - multiple select possible (ctrl+leftMouseClick) or (ctrl+A) for all" | `
                        ForEach-Object { Remove-ADGroupMember -Identity $_.Name -Members $selectedUser.SamAccountName -Confirm } 
                }
                '8' {
                    Clear-Host
                    Show-SubMenuSearchUser 
                }
                Default {
                    Clear-Host
                    Show-SubMenuSearchUser 
                }
            }
        }
    }
    catch {
        Write-Host "`nFout bij het ophalen van de gegevens, probeer het nogmaals."
        Write-Host "ErrorMessage: $_`n"
        Show-SubMenuSearchUser
    }
}

function Show-UserDetails {
    param (
        [string]$SamAccountName
    )

    $userDetails = Get-ADUser -Filter { SamAccountName -eq $SamAccountName } -Properties *

    if ($userDetails) {
        Clear-Host
        Write-Host ("╔" + ("═" * 40) + "╗")
        Write-Host ("║" + (" " * 12) + "User Information" + (" " * 12) + "║")
        Write-Host ("╚" + ("═" * 40) + "╝")

        $domainPasswordPolicy = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge
        $days = $domainPasswordPolicy.Days

        $userDetails | 
        Select-Object Name, SamAccountName, EmailAddress, Title, Department, Office, telephoneNumber, Manager, LastLogonDate, LastBadPasswordAttempt, PasswordLastSet | 
        ForEach-Object {
            # Get all property names and calculate the maximum length
            $propertyNames = $_.PSObject.Properties.Name
            $maxLength = ($propertyNames | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
        
            # Iterate through each property and align the output
            $_.PSObject.Properties | ForEach-Object { 
                $formattedName = $_.Name.PadRight($maxLength)  # Pad property name to max length
                Write-Host " ${formattedName} : $($_.Value)"

            }
            
            if ($userDetails.PasswordExpired -eq $true) {
                $expiresOn = $userDetails.PasswordLastSet.AddDays($days)
                $expiresOverDays = $expiresOn.Subtract($(Get-Date))
                Write-Host " PasswordExpired        : " -NoNewline
                Write-Host -ForegroundColor Red "$($userDetails.PasswordExpired)" -NoNewline
                Write-Host " (Expired on: $($expiresOn))"
            }
            else {
                $expiresOn = $userDetails.PasswordLastSet.AddDays($days)
                $expiresOverDays = $expiresOn.Subtract($(Get-Date))
                $expiresOverDays = $expiresOverDays.ToString("dd'd:'hh'h:'mm'm:'ss's'")
                Write-Host " PasswordExpired        : " -NoNewline
                Write-Host -ForegroundColor Green "$($userDetails.PasswordExpired)" -NoNewline
                Write-Host " (Expires on: $($expiresOn) - $($expiresOverDays) remaining)"
            }
            if ($userDetails.LockedOut -eq $false) {
                Write-Host " LockedOut              : " -NoNewline
                Write-Host -ForegroundColor Green "$($userDetails.LockedOut)"
            }
            else {
                Write-Host " LockedOut              : " -NoNewline
                Write-Host -ForegroundColor Red "$($userDetails.LockedOut)" -NoNewline
                Write-Host " (LockoutTime: $($userDetails.AccountLockoutTime))"
            }
            if ($userDetails.Enabled -eq $true) {
                Write-Host " Enabled                : " -NoNewline
                Write-Host -ForegroundColor Green "$($userDetails.Enabled)"
            }
            else {
                Write-Host " Enabled                : " -NoNewline
                Write-Host -ForegroundColor Red "$($userDetails.Enabled)"
            }
        }    
        Write-Host ("═" * 42)
    }
    else {
        Write-Host "Could not retrieve details for user: $SamAccountName"
    }
}

function Get-ADGroupsOfUser {
    # "`n"
    $userGroups = Get-ADUser -Identity $selectedUser.SamAccountName -Properties MemberOf | Select-Object -ExpandProperty MemberOf
    $groupMembers = $userGroups | ForEach-Object { (Get-ADGroup $_).Name }
    if ($groupMembers) {
        # Write-Host ((═ * 10) + " MemberOf " + (═ * 10))
        Write-Host ("╔" + ("═" * 30) + "╗")
        Write-Host ("║" + (" " * 11) + "MemberOf" + (" " * 11) + "║")
        Write-Host ("╚" + ("═" * 30) + "╝")
        $groupMembers
    }
    else {
        Write-Host "No groups found"
    }
    "`n"
    Pause
}
   
function Get-ADUserInfo {
    param(
        [string[]] $user
    )

    if (-not $user) {
        $user = Read-Host -Prompt "Enter username"
    }

    $searchTerm = "*$user*"
    $filter = "Name -like '$searchTerm' -or SamAccountName -like '$searchTerm' -or UserPrincipalName -like '$searchTerm'"

    Get-ADUser -Filter $filter -Properties * | Select-Object Name, AccountLockoutTime, BadLogonCount, DistinguishedName, EmailAddress, Enabled, LockedOut,
    GivenName, HomeDirectory, HomeDrive, LastBadPasswordAttempt, LastLogonDate, LastPasswordSet, 
    PasswordExpired, PasswordLastSet, pwdLastSet, SamAccountName, UserPrincipalName, Title, Office, telephoneNumber, `
    @{label = 'MemberOf'; expression = { ($_.MemberOf | ForEach-Object { (Get-ADGroup $_).Name } | Sort-Object) -join "`n" } } | Format-List
    
}

function Show-SubMenuSearchUser {
    while ($true) {

        New-Menu -title "Sub Menu" -options @("Back To Main Menu")

        Search-User

        $value = Read-Host "Make a selection"

        switch ($value) {
            "1" {
                main
            }
            Default {
                main
                Write-Host "Invalid option, please try again" 
            }
        }
    }
}

function main {
    while ($true) {

        Clear-Host

        New-Menu -title "Main Menu" -options @("Search User", "Get User Info", "Search AD Accounts", "Search AD Groups", "Custom Command", "Quit")

        $value = Read-Host "Make a selection, (default is `"1`")"
        
        switch ($value) {
            "1" {
                Clear-Host
                Show-SubMenuSearchUser
            }
            "2" {
                Get-ADUserInfo
                Pause
            }
            "3" {
                Show-SearchMenu
            }
            "4" {
                Show-SubMenuSearchGroup
            }
            "5" {
                Write-Host "Entering custom PowerShell Command Prompt. Type 'exit' to leave." -ForegroundColor Cyan
                powershell.exe -NoExit
            }
            "6" {
                Write-Host "Exiting..."
                exit
            }
            Default {
                Clear-Host
                Show-SubMenuSearchUser
                Write-Host "Invalid option, please try again" 
            }
        }
    }
}

main
