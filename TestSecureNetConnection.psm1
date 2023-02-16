<#PSScriptInfo

    .VERSION 1.0.0

    .GUID 4cc61e09-5b4c-415e-b97d-2170f64823e4

    .AUTHOR Anthony J. Raymond

    .COMPANYNAME

    .COPYRIGHT (c) 2022 Anthony J. Raymond

    .TAGS test secure connection tcp ssl tls

    .LICENSEURI https://github.com/CodeAJGit/posh/blob/master/LICENSE

    .PROJECTURI https://github.com/CodeAJGit/posh

    .ICONURI

    .EXTERNALMODULEDEPENDENCIES

    .REQUIREDSCRIPTS

    .EXTERNALSCRIPTDEPENDENCIES

    .RELEASENOTES
        Packaged in TestSecureNetConnection Module

    .PRIVATEDATA

#>

<#

    .DESCRIPTION
        Displays diagnostic information for a secure connection.

    .EXAMPLE
        Test-SecureNetConnection -ComputerName google.com -Port 443

    .PARAMETER ComputerName
        Specifies the Domain Name System (DNS) name or IP address of the target computer.

    .PARAMETER SslProtocol
        Sets the SSL/TLS protocols that are permissible for the connection.

    .PARAMETER Port
        Specifies the TCP port number on the target computer.

    .PARAMETER SkipCertificateCheck
        Skips certificate validation checks.

    .PARAMETER Timeout
        Sets the timeout value in milliseconds for the protocol tests.

    .PARAMETER Force
        Allows the cmdlet to enable protocols that would otherwise be disabled.

#>
function Test-SecureNetConnection {
    [CmdletBinding()]
    [OutputType([object])]

    ## PARAMETERS #############################################################
    param (
        [Parameter(
            Mandatory,
            Position = 0,
            ValueFromPipelineByPropertyName,
            ValueFromPipeline
        )]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $ComputerName,

        [Parameter()]
        [System.Collections.Generic.List[System.Security.Authentication.SslProtocols]]
        $SslProtocol = "None",

        [Parameter()]
        [int]
        [ValidateRange(1, 65535)]
        $Port = 443,

        [Parameter()]
        [switch]
        $SkipCertificateCheck,

        [Parameter()]
        [int]
        $Timeout = 15000,

        [Parameter()]
        [switch]
        $Force
    )

    ## BEGIN ##################################################################
    begin {
        Write-Verbose "start command execution"
        $SaveProgressPreference = $Global:ProgressPreference
        $Global:ProgressPreference = "SilentlyContinue"

        # https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
        $RegistryMap = @{
            [System.Security.Authentication.SslProtocols]::Ssl2  = "Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"
            [System.Security.Authentication.SslProtocols]::Ssl3  = "Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"
            [System.Security.Authentication.SslProtocols]::Tls   = "Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"
            [System.Security.Authentication.SslProtocols]::Tls11 = "Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"
            [System.Security.Authentication.SslProtocols]::Tls12 = "Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
            [System.Security.Authentication.SslProtocols]::Tls13 = "Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client"
        }

        # https://docs.microsoft.com/en-us/dotnet/api/system.security.authentication.sslprotocols
        # Allows the operating system to choose the best protocol to use, and to block protocols that are not secure.
        if ($SslProtocol.Remove([System.Security.Authentication.SslProtocols]::None)) {
            $SslProtocol.Add([System.Security.Authentication.SslProtocols]::Ssl2)
            $SslProtocol.Add([System.Security.Authentication.SslProtocols]::Ssl3)
            $SslProtocol.Add([System.Security.Authentication.SslProtocols]::Tls)
            $SslProtocol.Add([System.Security.Authentication.SslProtocols]::Tls11)
            $SslProtocol.Add([System.Security.Authentication.SslProtocols]::Tls12)
            $SslProtocol.Add([System.Security.Authentication.SslProtocols]::Tls13)
        }

        # https://docs.microsoft.com/en-us/dotnet/api/system.security.authentication.sslprotocols
        # Default permits only the Secure Sockets Layer (SSL) 3.0 or Transport Layer Security (TLS) 1.0 protocols to be negotiated.
        if ($SslProtocol.Remove([System.Security.Authentication.SslProtocols]::Default)) {
            $SslProtocol.Add([System.Security.Authentication.SslProtocols]::Ssl3)
            $SslProtocol.Add([System.Security.Authentication.SslProtocols]::Tls)
        }

        $ProtocolToRemove = [System.Collections.Generic.List[System.Security.Authentication.SslProtocols]] @()
        $DisableOnExit = [System.Collections.Generic.List[System.Security.Authentication.SslProtocols]] @()
        foreach ($Protocol in $SslProtocol) {
            Write-Verbose "$Protocol : start registry check"
            if (-not ($RegistryProperty = Get-ItemProperty -Path $RegistryMap[$Protocol] -ErrorAction SilentlyContinue).Enabled -and $null -ne $RegistryProperty) {
                Write-Verbose "$Protocol : disabled"
                if ($Force) {
                    Write-Verbose "$Protocol : force flag detected, set registry to enabled"
                    try {
                        Set-ItemProperty -Path $RegistryMap[$Protocol] -Name Enabled -Type DWord -Value 1 -ErrorAction Stop
                        $DisableOnExit.Add($Protocol)
                    } catch {
                        $ProtocolToRemove.Add($Protocol)
                        switch ($_.Exception) {
                            { $_ -is [System.Security.SecurityException] } { Write-Error "[$Protocol] The attempt to enable the protocol failed because access was denied."; break }
                            default { Write-Error "[$Protocol] An error of type $( $_.GetType().FullName ) has occured." }
                        }
                    }
                } else {
                    $ProtocolToRemove.Add($Protocol)
                    Write-Warning "[$Protocol] The protocol will be skipped because it is not enabled on the client."
                }
            } else {
                Write-Verbose "$Protocol : enabled"
            }
        }
        $ProtocolToRemove.ToArray().ForEach({ $null = $SslProtocol.Remove($_) })
    }

    ## PROCESS ################################################################
    process {
        foreach ($Computer in $ComputerName) {
            Write-Verbose "$Computer : start connection"
            $NetConnection = Test-NetConnection -ComputerName $Computer -Port $Port -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

            if (-not $NetConnection.RemoteAddress) {
                Write-Warning "[$Computer] The connection failed because the host does not exist."
            } elseif (-not $NetConnection.TcpTestSucceeded) {
                Write-Warning "[$Computer] The connection failed because the host refused the attempt."
            }

            $Hashtable = [ordered] @{
                ComputerName     = $NetConnection.ComputerName
                RemoteAddress    = $NetConnection.RemoteAddress
                RemotePort       = $NetConnection.RemotePort
                SourceAddress    = $NetConnection.SourceAddress
                PingSucceeded    = $NetConnection.PingSucceeded
                TcpTestSucceeded = $NetConnection.TcpTestSucceeded
            }

            if ($NetConnection.TcpTestSucceeded) {
                foreach ($Protocol in ($SslProtocol | Select-Object -Unique | Sort-Object)) {
                    Write-Verbose "$Computer : start $Protocol test"
                    try {
                        $TcpClient = [System.Net.Sockets.TcpClient]::new()
                        $TcpClient.SendTimeout = $Timeout
                        $TcpClient.ReceiveTimeout = $Timeout

                        # Connect (<string> hostname, <int> port);
                        $TcpClient.Connect($Computer, $Port)

                        try {
                            $SslStream = if ($SkipCertificateCheck) {
                                # SslStream (<System.IO.Stream> innerStream, <bool> leaveInnerStreamOpen, <System.Net.Security.RemoteCertificateValidationCallback> userCertificateValidationCallback);
                                [System.Net.Security.SslStream]::new($TcpClient.GetStream(), $true, ([System.Net.Security.RemoteCertificateValidationCallback] { $true }))
                            } else {
                                # SslStream (<System.IO.Stream> innerStream, <bool> leaveInnerStreamOpen);
                                [System.Net.Security.SslStream]::new($TcpClient.GetStream(), $true)
                            }
                            $SslStream.WriteTimeout = $Timeout
                            $SslStream.ReadTimeout = $Timeout

                            # AuthenticateAsClient (<string> targetHost, <System.Security.Cryptography.X509Certificates.X509CertificateCollection> clientCertificates, <System.Security.Authentication.SslProtocols> enabledSslProtocols, <bool> checkCertificateRevocation);
                            $SslStream.AuthenticateAsClient($Computer, $null, $Protocol, (-not $SkipCertificateCheck))
                        } catch {
                            switch ($_.Exception) {
                                { $_ -is [System.Management.Automation.MethodInvocationException] } { break }
                                default { Write-Warning "[$Protocol] An error of type $( $_.GetType().FullName ) has occured." }
                            }
                        } finally {
                            $Hashtable["${Protocol}TestSucceeded"] = [bool] $SslStream.IsAuthenticated
                            $SslStream.Dispose()
                        }
                        $TcpClient.Dispose()
                    } catch {
                        switch ($_.Exception) {
                            { $_ -is [System.Management.Automation.MethodInvocationException] } { Write-Error "[$Protocol] The connection failed because the timeout period was reached, or the host refused the attempt."; break }
                            default { Write-Error "[$Protocol] An error of type $( $_.GetType().FullName ) has occured." }
                        }
                    }
                }
            }
            New-Object -TypeName psobject -Property $Hashtable
        }
    }

    ## END ####################################################################
    end {
        Write-Verbose "start command cleanup"
        foreach ($Protocol in $DisableOnExit) {
            Write-Verbose "$Protocol : set registry to disabled"
            Set-ItemProperty -Path $RegistryMap[$Protocol] -Name Enabled -Type DWord -Value 0
        }

        $Global:ProgressPreference = $SaveProgressPreference

        $null = [System.GC]::GetTotalMemory($true)
    }
}


Set-Alias -Name TSNC -Value Test-SecureNetConnection
Export-ModuleMember -Function Test-SecureNetConnection -Alias TSNC
