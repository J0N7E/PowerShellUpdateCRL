<#
 .SYNOPSIS
    PowerShell Update CRL

 .DESCRIPTION
    Itterate certificates for CDP and AIA extensions
    Download CRL from distribution point, if successful and new crl exist, remove cache

 .NOTES
    AUTHOR Jonas Henriksson
    CREDIT TO Vadims Podāns for ASN.1 and OCSP encoding
    https://social.technet.microsoft.com/Forums/windows/en-US/e86bdf17-8902-4f74-b5d4-7ca60b99e185/ocsp-issues

 .LINK
    https://github.com/J0N7E

 .NOTES
    Register scheduled task with:

    @{
        TaskName    = "PowerShell Update CRL"
        Description = 'Updates CRL for all certificates every 1 minute and purge caches if successfull'
        TaskPath    = '\'
        Action      =
        @{
            Execute          = '.\PowerShellUpdateCRL.vbs'
            WorkingDirectory = "$($PWD.Path)"
        } | ForEach-Object {
            New-ScheduledTaskAction @_
        }
        Trigger     = New-ScheduledTaskTrigger -Once -At (Get-Date -Format "yyyy-MM-dd HH:00") -RepetitionInterval (New-TimeSpan -Minutes 1)
        Principal   = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545'
        Settings    = New-ScheduledTaskSettingsSet -MultipleInstances Parallel
    } | ForEach-Object {
        Register-ScheduledTask @_
    }

 .NOTES
    Register event source with:

    foreach ($EventSource in @('PowerShell Update CRL'))
    {
        New-EventLog -LogName Application -Source $EventSource
    }

 .NOTES
    Debug event source:

    foreach ($EventSource in @('PowerShell Update CRL'))
    {
        #Check registered event source exist with:
        [Diagnostics.EventLog]::SourceExists($EventSource)

        #Check which log registered event source is registered under
        [Diagnostics.EventLog]::LogNameFromSourceName($EventSource,'.')

        #Remove registered event with:
        #[Diagnostics.EventLog]::DeleteEventSource($EventSource)
    }
#>

try
{
    #######
    # Func
    #######

    function Get-ASN1Length
    {
        param
        (
            [Parameter(Mandatory=$true)]
            [Array]$RawData,
            [Parameter(Mandatory=$true)]
            [Int]$Offset
        )

        if ($RawData[$Offset + 1] -lt 128)
        {
          $Padding = 0
          $LengthBytes = 1
          $PayLoadLength = $RawData[$Offset + 1]
          $FullLength = $Padding + $LengthBytes + $PayLoadLength + 1
        }
        else
        {
          $Padding = 1
          $LengthBytes = $RawData[$Offset + 1] - 128
          $PayLoadLength = [uint32] "0x$(-join ($RawData[($Offset + 2)..($Offset + 1 + $LengthBytes)] | ForEach-Object { "{0:x2}" -f $_ }))"
          $FullLength = $Padding + $LengthBytes + $PayLoadLength + 1
        }

        Write-Output -InputObject (New-Object PSObject -Property ([ordered]@{

            FullLength    = $FullLength
            Padding       = $Padding
            LengthBytes   = $LengthBytes
            PayLoadLength = $PayLoadLength
        }))
    }

    function New-ASN1Structure
    {
        param
        (
            [ArgumentCompleter({

                $Structures =
                @{
                    'Boolean' = 1
                    'Integer' = 2
                    'BitString' = 3
                    'OctetString' = 4
                    'OID' = 6
                    'UTF8String' = 12
                    'IA5String' = 22
                    'UTCTime' = 23
                    'GeneralizedTime' = 24
                    'Sequence' = 48
                }

                if ($args[4].GetStructure)
                {
                    $Structures
                }
                else
                {
                    $Structures.Keys
                }
            })]
            [string]$Structure = "Sequence",

            [Parameter(Mandatory=$true)]
            [Byte[]]$RawData
        )

        if ($RawData.Count -lt 128)
        {
            $LengthBytes = $RawData.Count
            $ComputedRawData = ,$LengthBytes + $RawData
        }
        else
        {
            $LengthBytes = "{0:x2}" -f $RawData.Count

            if (($RawData.Count % 2) -ne 0)
            {
                $LengthBytes = "0$LengthBytes"
            }

            [Byte[]]$LengthBytes = $LengthBytes -split "([a-f0-9]{2})" | Where-Object { $_ } | ForEach-Object { [Convert]::ToByte($_, 16) }

            $PaddingByte = 128 + $LengthBytes.Count
            $ComputedRawData = ,$PaddingByte + $LengthBytes + $RawData
        }

        # Get structures from argumentcompleter scriptblock
        $StructureHash = Invoke-Command -ScriptBlock $MyInvocation.MyCommand.Parameters.Item("Structure").Attributes.ScriptBlock `
                                        -ArgumentList @($null, $null, $null, $null, @{ GetStructure = $True })
        # Return
        Write-Output -InputObject (,$StructureHash[$Structure] + $ComputedRawData)
    }

    function New-EncodedOcspRequest
    {
        param
        (
            [ValidateSet('MD5', 'SHA1', 'SHA256')]
            [String]$HashAlgorithm = 'SHA1',
            [Parameter(Mandatory=$true)]
            [Byte[]]$IssuerName,
            [Parameter(Mandatory=$true)]
            [Byte[]]$IssuerKey,
            [Parameter(Mandatory=$true)]
            [Byte[]]$SerialNumber
        )

        # Get hash oid
        $HashOidCollection = New-Object Security.Cryptography.OidCollection
        $HashOidCollection.Add((New-Object Security.Cryptography.Oid("1.3.14.3.2.26", $HashAlgorithm))) > $null
        $HashRawData = (New-Object Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension $HashOidCollection, $false).RawData

        switch($HashAlgorithm)
        {
            'MD5'
            {
                $HashObject = [Security.Cryptography.MD5]::Create()
            }

            'SHA256'
            {
                $HashObject = [Security.Cryptography.SHA256]::Create()
            }

            default
            {
                $HashObject = [Security.Cryptography.SHA1]::Create()
            }
        }

        # https://www.rfc-editor.org/rfc/rfc6960.html#section-4.1.1
        Write-Output -InputObject (

            [Uri]::EscapeDataString(

                [Convert]::ToBase64String((

                    # OcspRequest
                    New-ASN1Structure -Structure 'Sequence' -RawData (

                        # TbsRequest
                        New-ASN1Structure -Structure 'Sequence' -RawData (

                            # Sequence of requests
                            New-ASN1Structure -Structure 'Sequence' -RawData (

                                # Request
                                New-ASN1Structure -Structure 'Sequence' -RawData (

                                    # CertID
                                    New-ASN1Structure -Structure 'Sequence' -RawData (

                                        # HashAlgorithm
                                        (New-ASN1Structure -Structure 'Sequence' -RawData ($HashRawData[2..($HashRawData.Count - 1)] + 5,0)) +

                                        # IssuerNameHash
                                        (New-ASN1Structure -Structure 'OctetString' -RawData $HashObject.ComputeHash($IssuerName)) +

                                        # IssuerKeyHash
                                        (New-ASN1Structure -Structure 'OctetString' -RawData $HashObject.ComputeHash($IssuerKey)) +

                                        # SerialNumber
                                        (New-ASN1Structure -Structure 'Integer' -RawData ($SerialNumber))
                                    )
                                )
                            )
                        )
                    )
                ))
            )
        )
    }

    function Get-OcspRequestRawData
    {
        param
        (
            [Parameter(Mandatory=$true)]
            [Security.Cryptography.X509Certificates.X509Certificate]$Certificate
        )

        # Create x509Chain
        $X509Chain = New-Object Security.Cryptography.X509Certificates.X509Chain
        $X509Chain.ChainPolicy.RevocationMode = "NoCheck"
        $X509Chain.Build($Certificate) > $null

        Write-Output -InputObject @{

            IssuerName = $Certificate.IssuerName.RawData
            IssuerKey = $X509Chain.ChainElements[1].Certificate.PublicKey.EncodedKeyValue.RawData
            SerialNumber = $Certificate.SerialNumber -split "([a-f0-9]{2})" | Where-Object { $_ } | ForEach-Object { [Convert]::ToByte($_, 16) }
        }
    }

    function Try-WebRequest
    {
        param
        (
            [Parameter(Mandatory=$true)]
            [String]$Uri,
            [ValidateSet('Get', 'Head')]
            [String]$Method = 'Get'
        )

        $Request = $null

        try
        {
            # Try request header
            $Request = Invoke-WebRequest -Uri $Uri -Method $Method
        }
        catch
        {
            # > $null
        }

        Write-Output -InputObject $Request
    }

    function Write-Log
    {
        param
        (
            [ValidateSet('Error', 'Warning', 'Information')]
            [String]$EntryType,
            [Parameter(Mandatory=$true)]
            [String]$Message
        )

        # Check if powersehll is started as non interactive
        if ($NonInteractive)
        {
            Write-EventLog -LogName Application `
                           -Source 'PowerShell Update CRL' `
                           -EntryType $EntryType `
                           -EventId 1234 `
                           -Message $Message `
                           -Category 0
        }
        else
        {
            switch ($EntryType)
            {
                'Error'
                {
                    Write-Error -Message $Message
                }

                'Warning'
                {
                    Write-Warning -Message $Message
                }

                default
                {
                    Write-Verbose -Message $Message -Verbose
                }
            }
        }
    }

    #######
    # Init
    #######

    $CdpHashtable = @{}
    $OcspHashtable = @{}
    $NonInteractive = [Environment]::GetCommandLineArgs() | Where-Object { $_ -eq '-NonInteractive' }

    #######
    # Enum
    #######

    # Itterate certificates
    foreach($Cert in (Get-Item -Path Cert:\CurrentUser\My\*))
    {
        # Check cdp extension
        if ($Cert.Extensions['2.5.29.31'])
        {
            # Decode cdp extension
            $CdpUrl = (New-Object Security.Cryptography.AsnEncodedData(
                '2.5.29.31',
                $Cert.Extensions['2.5.29.31'].RawData

            # Get cdp url
            )).Format($false) | Where-Object { $_ -match 'URL=(.*?)(?=$|,|\s\()' } | ForEach-Object { $Matches[1] }

            if (-not $CdpHashtable.Contains("$CdpUrl"))
            {
                $CdpHashtable.Add("$CdpUrl", @{

                    Url = $CdpUrl
                    Issuer = $Cert.Issuer | Where-Object { $_ -match 'CN=(.*?)(?:,|$)' } | ForEach-Object { $Matches[1] }
                })
            }
        }

        # Chek aia extension
        if  ($Cert.Extensions['1.3.6.1.5.5.7.1.1'])
        {
            # Decode aia extension
            $OcspUrl = (New-Object Security.Cryptography.AsnEncodedData(
                '1.3.6.1.5.5.7.1.1',
                $Cert.Extensions['1.3.6.1.5.5.7.1.1'].RawData

            # Get ocsp url
            )).Format($false) | Where-Object { $_ -match '\(1.3.6.1.5.5.7.48.1\), Alternative Name=URL=(.*)$' } | ForEach-Object { $Matches[1] }

            if ($OcspUrl)
            {
                if (-not $OcspHashtable.Contains("$CdpUrl"))
                {
                    $OcspHashtable.Add("$CdpUrl", @{ Url = $OcspUrl })
                }
            }
        }
    }

    #######
    # Exec
    #######

    foreach($Cdp in $CdpHashtable.GetEnumerator())
    {
        # Get cdp header
        $Head = Try-WebRequest -Uri "$($Cdp.Value.Url)" -Method Head

        # Header request successfull
        if ($Head -and $Head.StatusCode -eq '200')
        {
            # Get etag from header
            $ETag = $Head.Headers["ETag"] | Where-Object { $_ -match '"(.*):0"' } | ForEach-Object { $Matches[1] }

            # Get old etag
            $IssuerNoSpace = $Cdp.Value.Issuer.Replace(' ', '_')
            $OldETag = [Environment]::GetEnvironmentVariable("Crl_$($IssuerNoSpace)_ETag", 'User')

            # Check if to download crl
            if(-not $ETag -or $ETag -ne $OldETag)
            {
                # Request crl
                $Request = Try-WebRequest -Uri "$($Cdp.Value.Url)"

                # Request successfull
                if($Request -and $Request.StatusCode -eq '200')
                {
                    # Get filename
                    $CdpFile = $Cdp.Value.Url.Substring($Cdp.Value.Url.LastIndexOf('/') + 1)

                    # Save crl to temp
                    Set-Content -Value $Request.Content -LiteralPath "$env:TEMP\$CdpFile" -Encoding Byte

                    if(-not $ETag)
                    {
                        # Initialize
                        $OldCrlNumber = $null

                        # Check old and new crl
                        foreach ($Arg in "-store ca `"$($Cdp.Value.Issuer)`"", "`"$env:TEMP\$CdpFile`"")
                        {
                            # Get crl number
                            $CrlNumber = Invoke-Expression -Command "certutil $Arg" | Where-Object { $_ -match 'CRL Number=(.*)$' } | ForEach-Object { $Matches[1] }

                            if (-not $CrlNumber)
                            {
                                $CrlNumber = 0
                            }

                            # Convert from hex
                            $CrlNumber = [uint32] "0x$CrlNumber"

                            # Set old crl number
                            if (-not $OldCrlNumber)
                            {
                                $OldCrlNumber = $CrlNumber
                            }
                        }
                    }

                    if($ETag -or $CrlNumber -gt $OldCrlNumber)
                    {
                        # Remove old crl
                        certutil -user -delstore ca "$($Cdp.Value.Issuer)" > $null

                        Write-Log -EntryType Information -Message "Updating `"$CdpFile`" for $(whoami)"
                        certutil -user -addstore ca "$env:TEMP\$CdpFile" > $null

                        # Remove crl cache
                        certutil -urlcache "$([Uri]::EscapeUriString($Cdp.Value.Url))" delete > $null

                        if ($OcspHashtable.Contains($Cdp.Name))
                        {
                            # Remove ocsp cache
                            certutil -urlcache $OcspHashtable.Item($Cdp.Name).Url delete > $null
                        }

                        if($ETag)
                        {
                            # Remember etag
                            [Environment]::SetEnvironmentVariable("Crl_$($IssuerNoSpace)_ETag", $ETag, 'User')
                        }
                    }

                    # Remove crl from temp
                    Remove-Item -Path "$env:TEMP\$CdpFile" -Force
                }
            }
        }
    }

    # Remove old environment variables
    foreach($Var in (Get-Item -Path Env:\Crl_*_ETag))
    {
        if($Var.Name.Substring(4, $Var.Name.Length - 9).Replace('_', ' ') -notin $CdpHashtable.Values.Issuer)
        {
            [Environment]::SetEnvironmentVariable($Var.Name, $null, 'User')
        }
    }
}
catch
{
   Write-Log -EntryType Error -Message $_
}

# SIG # Begin signature block
# MIIeuAYJKoZIhvcNAQcCoIIeqTCCHqUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBDaLjW4RCCMdmS
# Oxy/ecmltW9ZZ5Ol6aaz/+jflYQjaKCCGBQwggUHMIIC76ADAgECAhB0XMs0val9
# mEnBo5ekK6KYMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNVBAMMBUowTjdFMB4XDTIz
# MDkwNzE4NTk0NVoXDTI4MDkwNzE5MDk0NFowEDEOMAwGA1UEAwwFSjBON0UwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDRw1gJO1wnpdRIbqVo1gfsnMV8
# kxOJBp/FDV1XxyN0njKwlcA6zyudii33AqXYWUojp4xPoXzBGkVuoqqZOkSXHMz5
# /OScP3fe4QEtIC6X9vSQuWvo9jaih0kLbRUEBTG2EVRiHsVyeLR3DPgSNckbGJ54
# MMtlhFPchHo/N7BpaGrUtdjd+F59hDVDaeoe6VVYPVaC5yAgUR9QkJZw69+YkET4
# S+Q09WgoCoXEnrVnnjPzLq0iN0rdSOrhuBE5CouwUwr6YgjU6pwtEoyBaRUhL2cd
# 8UXLzVUgy9+Bo6mhJUtq1ujECc6afx26wkDYMwfo4vTdIgFv8XATvrvWyO0a4ZGn
# 6eU+eS+hWoURP2iVlYPGUY555F1NzeOVwQ9v1cumIaOVB8x+TjJxLCtomqfVxgO9
# JeHcrqW/Q55Itr9VBGUSk6a20oEQj94UwrvoNmkbEW+/XE6DWmHf7TWEJug5d4+7
# 2pI2TmGcisERv16qSzevlkN+uUTCMVSF32Qt7ZQoRocrscj37fHVaFOA1EpbMrOp
# RwX1pWWkNBGmWptQwkTMzHNFQiTTU0OrDjqCNRh63pWcg+qdAB7ZstaoMx4vdfo/
# twAfHDTnI403nUyrIEV1gLUyJ5i5Tgw6gh8g3ozq8Qaftq+PD1rhel+ByG23LZ42
# AhGD4q4ndfG13VEONQIDAQABo10wWzAOBgNVHQ8BAf8EBAMCBaAwKgYDVR0lBCMw
# IQYIKwYBBQUHAwMGCSsGAQQBgjdQAQYKKwYBBAGCNwoDBDAdBgNVHQ4EFgQUWNAE
# eD3ij461l5HFCgfSYoXMwCkwDQYJKoZIhvcNAQELBQADggIBAFKCUuzQ8KfuDfqI
# ZG+peeD9+r7qcvdlIt4tRdIOgVcqEncrrAVKIcEm0Fi1Zzs6cchsiDUUUUCLkYg/
# nowzCY3g2hjQOsE3QaWHgmr+WG6JqHnOz/2/9pS+3C8EPg1VfQb/Am5G5fr3tRBm
# u2RaeKcHjoEw9T6ASDVy2fRXjNDd9rOtyYmoP3EjAqU5ey/E4A7k4nnW5x2y5sPp
# CQlr77hsZ3keGgLz87XybHPphhqA6ddYk5vJuTB2QML0xSPLnBk0C/jwORQz44Ct
# t8zdml9wBVOcOt+7Omg4pORx2Bs37hVckL+XLUP3x/4ikQ7DVQi1fweDrtZ9T2xd
# whj5+CHMc8cXzri+nYX8bvmLTYyip5Gl47eC7C6bcNsoKQq2zlLVBecTumZ6p7hT
# n3mMJWEQt4HqJ+u+PS6VKU5TkYS3A1jlUvRPdwd6AGa1BcV9ChPq9ugXqb0juRWU
# oZPhYjwz9RBgJDZk/cdON1Ie31RwmyUYyoPGFuQYsfj0RI/mCFtF12WXbh2zDR0X
# 3qU4gSaEHTVQ0jPjROietordyS4l2euH/Z8dhvJwYeOSjCIxQlBqKFtkFEq8EeGs
# zs65D3oz2DwaTZEIip1fSU7yfbJLx+fMShZ7wVXATluADk3CXqJh2izO5tiCH6yJ
# Ux7YQVpSHQNdeltDcnGMwZ7mpUrXMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21Di
# CEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtE
# aWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzEx
# MTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBU
# cnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/
# 5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xuk
# OBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpz
# MpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7Fsa
# vOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qT
# XtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRz
# Km6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRc
# Ro9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADk
# RSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMY
# RJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4m
# rLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C
# 1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYD
# VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYD
# VR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkG
# CCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
# Y29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
# aUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmww
# EQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+g
# o3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0
# /4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnL
# nU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU9
# 6LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ
# 9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9X
# ql4o4rmUMIIGrjCCBJagAwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0B
# AQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVk
# IFJvb3QgRzQwHhcNMjIwMzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lD
# ZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKR
# N6mXUaHW0oPRnkyibaCwzIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZz
# lm34V6gCff1DtITaEfFzsbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1Oco
# LevTsbV15x8GZY2UKdPZ7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH
# 92GDGd1ftFQLIWhuNyG7QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRA
# p8ByxbpOH7G1WE15/tePc5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+g
# GkcgQ+NDY4B7dW4nJZCYOjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU
# 8lKVEStYdEAoq3NDzt9KoRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/
# FDTP0kyr75s9/g64ZCr6dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwj
# jVj33GHek/45wPmyMKVM1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQ
# EgN9XyO7ZONj4KbhPvbCdLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUae
# tdN2udIOa5kM0jO0zbECAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# HQYDVR0OBBYEFLoW2W1NhS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LS
# cV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEF
# BQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYy
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5j
# cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
# CwUAA4ICAQB9WY7Ak7ZvmKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftw
# ig2qKWn8acHPHQfpPmDI2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalW
# zxVzjQEiJc6VaT9Hd/tydBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQm
# h2ySvZ180HAKfO+ovHVPulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScb
# qyQeJsG33irr9p6xeZmBo1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLaf
# zYeHJLtPo0m5d2aR8XKc6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbD
# Qc1PtkCbISFA0LcTJM3cHXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0K
# XzM5h0F4ejjpnOHdI/0dKNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm
# 8heZWcpw8De/mADfIBZPJ/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9
# gdkT/r+k0fNX2bwE+oLeMt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8a
# pIUP/JiW9lVUKx+A+sDyDivl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBsIwggSq
# oAMCAQICEAVEr/OUnQg5pr/bP1/lYRYwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0y
# MzA3MTQwMDAwMDBaFw0zNDEwMTMyMzU5NTlaMEgxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjEgMB4GA1UEAxMXRGlnaUNlcnQgVGltZXN0YW1w
# IDIwMjMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCjU0WHHYOOW6w+
# VLMj4M+f1+XS512hDgncL0ijl3o7Kpxn3GIVWMGpkxGnzaqyat0QKYoeYmNp01ic
# NXG/OpfrlFCPHCDqx5o7L5Zm42nnaf5bw9YrIBzBl5S0pVCB8s/LB6YwaMqDQtr8
# fwkklKSCGtpqutg7yl3eGRiF+0XqDWFsnf5xXsQGmjzwxS55DxtmUuPI1j5f2kPT
# hPXQx/ZILV5FdZZ1/t0QoRuDwbjmUpW1R9d4KTlr4HhZl+NEK0rVlc7vCBfqgmRN
# /yPjyobutKQhZHDr1eWg2mOzLukF7qr2JPUdvJscsrdf3/Dudn0xmWVHVZ1KJC+s
# K5e+n+T9e3M+Mu5SNPvUu+vUoCw0m+PebmQZBzcBkQ8ctVHNqkxmg4hoYru8QRt4
# GW3k2Q/gWEH72LEs4VGvtK0VBhTqYggT02kefGRNnQ/fztFejKqrUBXJs8q818Q7
# aESjpTtC/XN97t0K/3k0EH6mXApYTAA+hWl1x4Nk1nXNjxJ2VqUk+tfEayG66B80
# mC866msBsPf7Kobse1I4qZgJoXGybHGvPrhvltXhEBP+YUcKjP7wtsfVx95sJPC/
# QoLKoHE9nJKTBLRpcCcNT7e1NtHJXwikcKPsCvERLmTgyyIryvEoEyFJUX4GZtM7
# vvrrkTjYUQfKlLfiUKHzOtOKg8tAewIDAQABo4IBizCCAYcwDgYDVR0PAQH/BAQD
# AgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwIAYDVR0g
# BBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMB8GA1UdIwQYMBaAFLoW2W1NhS9z
# KXaaL3WMaiCPnshvMB0GA1UdDgQWBBSltu8T5+/N0GSh1VapZTGj3tXjSTBaBgNV
# HR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3JsMIGQBggrBgEF
# BQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29t
# MFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3J0MA0GCSqG
# SIb3DQEBCwUAA4ICAQCBGtbeoKm1mBe8cI1PijxonNgl/8ss5M3qXSKS7IwiAqm4
# z4Co2efjxe0mgopxLxjdTrbebNfhYJwr7e09SI64a7p8Xb3CYTdoSXej65CqEtcn
# hfOOHpLawkA4n13IoC4leCWdKgV6hCmYtld5j9smViuw86e9NwzYmHZPVrlSwrad
# OKmB521BXIxp0bkrxMZ7z5z6eOKTGnaiaXXTUOREEr4gDZ6pRND45Ul3CFohxbTP
# mJUaVLq5vMFpGbrPFvKDNzRusEEm3d5al08zjdSNd311RaGlWCZqA0Xe2VC1UIyv
# Vr1MxeFGxSjTredDAHDezJieGYkD6tSRN+9NUvPJYCHEVkft2hFLjDLDiOZY4rbb
# PvlfsELWj+MXkdGqwFXjhr+sJyxB0JozSqg21Llyln6XeThIX8rC3D0y33XWNmda
# ifj2p8flTzU8AL2+nCpseQHc2kTmOt44OwdeOVj0fHMxVaCAEcsUDH6uvP6k63ll
# qmjWIso765qCNVcoFstp8jKastLYOrixRoZruhf9xHdsFWyuq69zOuhJRrfVf8y2
# OMDY7Bz1tqG4QyzfTkx9HmhwwHcK1ALgXGC7KP845VJa1qwXIiNO9OzTF/tQa/8H
# dx9xl0RBybhG02wyfFgvZ0dl5Rtztpn5aywGRu9BHvDwX+Db2a2QgESvgBBBijGC
# BfowggX2AgEBMCQwEDEOMAwGA1UEAwwFSjBON0UCEHRcyzS9qX2YScGjl6Qropgw
# DQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgUPL29TTW7GzpSxKzK4esB/slKOthWZT045Y0
# DJhPn+swDQYJKoZIhvcNAQEBBQAEggIAL6FgAjCqM76t0NC/NIncO5PJfLZfGejF
# ZDs9FUvp2vXBNnvZbPvvk1SBBgrQamJPa9k+2kTTJ6KjlMCUhtfWRdmmO1r/RJmP
# M9w9LExlirIB87rJrCm6KRCM0Dbh+PokDkXKuQwm1q1x78PNrE7y+iPudIjFXIUq
# 6zEdzDx4u2avqcsbrF3l3R7vwmyW8tTh7KVvbpuoDgzMVC/pywa2+xIKPjmQdSEb
# yeQHl3HxKqRWrn3OXQDSIiELbZpm0kV567FOhNrqg9AKa5gAgjZIxRb2fB18YuT9
# b5uMYRCryBvdfhmJeKED3UeTiUAHd4IBS4pc/xCindlst6YkefkUi+/Uls85D6kD
# 2UxjIF8SMoDsP4WQsK3px5R78aIXe87hnED3Q7wvx/hICmEyQVr8qS0uOlZXz2m7
# qCqcg9diPUUKeQx/uh8hcUlpAOEn3AHfHMWSzx1JubbmhSEVGXZ3hFHKJs2NggfG
# ksPZVWL7s583ypaAcd677WniSLCoYNw98OUDYSaaKGcqfb3auciba/si5hSi2xrc
# j79qzkyKNT+axzb48dzLQslcU1D+1EST1yeHOvQyL6qS8zqFRmpW50XNdIuWyTGF
# woLMqCDN692YqzZGMKG060XGzjKuA1frirQH9joTX0VfMymXi03vPPsYPVsTs4En
# +dSSXxjVwyChggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lD
# ZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAF
# RK/zlJ0IOaa/2z9f5WEWMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjMxMDA2MDcyNDUwWjAvBgkqhkiG
# 9w0BCQQxIgQgrPIJIG8s/KEOrAEBJwnKV49z7XgGzDgIk3wFQ5JzSuwwDQYJKoZI
# hvcNAQEBBQAEggIASZ3ru5YUTiJxhIuV8dk+o+aVSzWcuUGhkP+ArZen6Aiip8kP
# yLNWMcyMncFuE6V6M4Usv26hU0hpJsvPoTU1PuCD83Y9hVHLwtR31+04cG9q0x8V
# Fu5n9GHHXBkEh0zyUjSeK+wQhKM7yFe2kX42PHOL+sCFO8yCpBRuOLyi3XyKf0eR
# /CzBVyvVZmkNAtcQ56I4CXB/ZUnjnqH2B5rs9Gcq04MNQzBdpSBex6Rwq+dvndlj
# GLToAoRFvsuI8M1prejQzdjkX+iMPXk94h2Optnuyy0NXdaDSmGhA/zagjTiHNnZ
# dm9c155RqpImIY7xNhMCTZnjVCCe5RkF0VvwflCh/d/fcWo8RbYQB4yrDqdkP6WS
# 7g576+VbxyHwJ4wjOwjkJlDgY7J4/BoY3pgaJPQZ3kcwZl2RVh+ubVnUmqxKWups
# xrATuZ2tRhjxgfT2E6Uc59USF0RF19QmuIyzEYwAoU439jnKLOgryM6f2ZsvN36t
# hsjGKlO/YczmoPmtXMkfOxAs9BAwi6sHzAu2TFpXFZOV084bIVFyARtNDcf2TDgg
# dY0OaPBvto/7FhQ7wFFWIobBjK5vDYlkLuXslaG61OSrTCFLS/ysTNkFV/HVPXAW
# 9M8en3P+B6JWK3SXSI4kIDx3qSSj2ICGEsXa31bePGpPGtiN91QhcG/ymw4=
# SIG # End signature block
