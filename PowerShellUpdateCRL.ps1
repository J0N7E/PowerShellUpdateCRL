<#
 .SYNOPSIS
    PowerShell Update CRL

 .DESCRIPTION
    Itterate certificates for CDP and AIA extensions
    Download CRL from distribution point, if successful and new crl exist, remove cache

 .NOTES
    AUTHOR Jonas Henriksson
    CREDIT TO Vadims Podāns for ASN.1 and ocsp encoding
    https://social.technet.microsoft.com/Forums/windows/en-US/e86bdf17-8902-4f74-b5d4-7ca60b99e185/ocsp-issues

 .LINK
    https://github.com/J0N7E

 .NOTES
    Register scheduled task with:

    @{
        TaskName    = "PowerShell Update CRL"
        Description = 'Updates CRL for all certificates every 5 minutes and purge caches if successfull'
        TaskPath    = '\'
        Action      =
        @{
            Execute          = '.\PowerShellUpdateCRL.vbs'
            WorkingDirectory = "$($PWD.Path)"
        } | ForEach-Object {
            New-ScheduledTaskAction @_
        }
        Trigger     = New-ScheduledTaskTrigger -Once -At (Get-Date -Format "yyyy-MM-dd HH:00") -RepetitionInterval (New-TimeSpan -Minutes 5)
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
    # Init
    #######

    $CdpHashtable = @{}
    $OcspHashtable = @{}
    $NonInteractive = [Environment]::GetCommandLineArgs() | Where-Object { $_ -eq '-NonInteractive' }

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

    function New-OcspRequest
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

    function Get-OcspRequestParams
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

    function Convert-ToSha256Base64Url
    {
        param
        (
            [Parameter(Mandatory=$true)]
            [String]$String
        )

        begin
        {
            $Sha256 = [Security.Cryptography.SHA256]::Create()
        }

        process
        {
            Write-Output -InputObject ([Uri]::EscapeDataString([Convert]::ToBase64String($Sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($String)))))
        }

        end
        {
            $Sha256.Dispose()
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
    # Enum
    #######

    # Itterate certificates
    foreach($Cert in (Get-Item -Path Cert:\*\My\*))
    {
        # Check cdp extension
        if ($Cert.Extensions['2.5.29.31'])
        {
            # Decode cdp extension
            $CdpUrl = (New-Object Security.Cryptography.AsnEncodedData(
                '2.5.29.31',
                $Cert.Extensions['2.5.29.31'].RawData

            # Get cdp url
            )).Format($false) | Where-Object { $_ -match 'URL=(.*?)(?=$|\s\()' } | ForEach-Object { $Matches[1] }

            if (-not $CdpHashtable.Contains("$CdpUrl"))
            {
                $CdpHashtable.Add("$CdpUrl", @{

                    Url = $CdpUrl
                    Issuer = $Cert.Issuer
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
                    $OcspHashtable.Add("$CdpUrl", (@{ Url = $OcspUrl } + (Get-OcspRequestParams -Certificate $Cert)))
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
            $OldETag = [Environment]::GetEnvironmentVariable("Crl_$(Convert-ToSha256Base64Url -String $Cdp.Value.Url)_ETag", 'User')

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
                    $CdpIssuerCn = $Cdp.Value.Issuer | Where-Object { $_ -match 'CN=(.*?)(?:,|$)' } | ForEach-Object { $Matches[1] }


                    # Save crl to temp
                    Set-Content -Value $Request.Content -LiteralPath "$env:TEMP\$CdpFile" -Encoding Byte

                    if(-not $ETag)
                    {
                        # Initialize
                        $OldCrlNumber = $null

                        # Check old and new crl
                        foreach ($Arg in "-store ca `"$CdpIssuerCn`"", "`"$env:TEMP\$CdpFile`"")
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
                        certutil -delstore ca "$CdpIssuerCn" > $null

                        Write-Log -EntryType Information -Message "Updating CRL `"$CdpFile`" for $(whoami)"
                        certutil -addstore ca "$env:TEMP\$CdpFile" > $null

                        # Remove crl cache
                        certutil -urlcache "$([Uri]::EscapeUriString($Cdp.Value.Url))" delete

                        # Check ocsp
                        if ($OcspHashtable.Contains($Cdp.Name))
                        {
                            certutil -urlcache $OcspHashtable.Item($Cdp.Name).Url delete
                        }

                        if($ETag)
                        {
                            # Remember etag
                            [Environment]::SetEnvironmentVariable("Crl_$(Convert-ToSha256Base64Url -String $Cdp.Value.Url)_ETag", $ETag, 'User')
                        }
                    }

                    # Remove crl from temp
                    Remove-Item -Path "$env:TEMP\$CdpFile" -Force
                }
            }
        }
    }
}
catch
{
   Write-Log -EntryType Error -Message $_
}

# SIG # Begin signature block
# MIIekQYJKoZIhvcNAQcCoIIegjCCHn4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUcwBThJKxoDuz75AlaLBymsZH
# TmKgghgSMIIFBzCCAu+gAwIBAgIQJTSMe3EEUZZAAWO1zNUfWTANBgkqhkiG9w0B
# AQsFADAQMQ4wDAYDVQQDDAVKME43RTAeFw0yMTA2MDcxMjUwMzZaFw0yMzA2MDcx
# MzAwMzNaMBAxDjAMBgNVBAMMBUowTjdFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAzdFz3tD9N0VebymwxbB7s+YMLFKK9LlPcOyyFbAoRnYKVuF7Q6Zi
# fFMWIopnRRq/YtahEtmakyLP1AmOtesOSL0NRE5DQNFyyk6D02/HFhpM0Hbg9qKp
# v/e3DD36uqv6DmwVyk0Ui9TCYZQbMDhha/SvT+IS4PBDwd3RTG6VH70jG/7lawAh
# mAE7/gj3Bd5pi7jMnaPaRHskogbAH/vRGzW+oueG3XV9E5PWWeRqg1bTXoIhBG1R
# oSWCXEpcHekFVSnatE1FGwoZHTDYcqNnUOQFx1GugZE7pmrZsdLvo/1gUCSdMFvT
# oU+UeurZI9SlfhPd6a1jYT/BcgsZdghWUO2M8SCuQ/S/NuotAZ3kZI/3y3T5JQnN
# 9l9wMUaoIoEMxNK6BmsSFgEkiQeQeU6I0YT5qhDukAZDoEEEHKl17x0Q6vxmiFr0
# 451UPxWZ19nPLccS3i3/kEQjVXc89j2vXnIW1r5UHGUB4NUdktaQ25hxc6c+/Tsx
# 968S+McqxF9RmRMp4g0kAFhBHKj7WhUVt2Z/bULSyb72OF4BC54CCSt1Q4eElh0C
# 1AudkZgj9CQKFIyveTBFsi+i2g6D5cIpl5fyQQnqDh/j+hN5QuI8D7poLe3MPNA5
# r5W1c60B8ngrDsJd7XnJrX6GdJd2wIPh1RmzDlmoUxVXrgnFtgzeTUUCAwEAAaNd
# MFswDgYDVR0PAQH/BAQDAgWgMCoGA1UdJQQjMCEGCCsGAQUFBwMDBgkrBgEEAYI3
# UAEGCisGAQQBgjcKAwQwHQYDVR0OBBYEFEPCLoNYgwyQVHRrBSI9l0nSMwnLMA0G
# CSqGSIb3DQEBCwUAA4ICAQBiMW8cSS4L1OVu4cRiaPriaqQdUukgkcT8iWGWrAHL
# TFPzivIPI5+7qKwzIJbagOM3fJjG0e6tghaSCPfVU+sPWvXIKF3ro5XLUfJut6j5
# qUqoQt/zNuWpI12D1gs1NROWnJgqe1ddmvoAOn5pZyFqooC4SnD1fT7Srs+G8Hs7
# Qd2j/1XYAphZfLXoiOFs7uzkQLJbhmikhEJQKzKE4i8dcsoucNhe2lvNDftJqaGl
# oALzu04y1LcpgCDRbvjU0YDStZwKSEj9jvz89xpl5tMrgGWIK8ghjRzGf0iPhqb/
# xFOFcKP2k43X/wXWa9W7PlO+NhIlZmTM/W+wlgrRfgkawy2WLpO8Vop+tvVwLdyp
# 5n4UxRDXBhYd78Jfscb0fwpsU+DzONLrJEwXjdj3W+vdEZs7YIwAnsCGf8NznXWp
# N9D7OzqV0PT2Szkao5hEp3nS6dOedw/0uKAz+l5s7WJOTLtFjDhUk62g5vIZvVK2
# E9TWAuViPmUkVugnu4kV4c870i5YgRZz9l4ih5vL9XMoc4/6gohLtUgT4FD0xKXn
# bwtl/LczkzDO9vKLbx93ICmNJuzLj+K8S4AAo8q6PTgLZyGlozmTWRa3SmGVqTNE
# suZR41hGNpjtNtIIiwdZ4QuP8cj64TikUIoGVNbCZgcPDHrrz84ZjAFlm7H9SfTK
# 8jCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAw
# ZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBS
# b290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUu
# ySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8
# Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0M
# G+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldX
# n1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4x7axxLVq
# GDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFE
# mjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6
# SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXf
# SwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b23
# 5kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ
# 6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRp
# L5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
# BBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1R
# i6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0
# cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADAN
# BgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVe
# qRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq3vot
# Vs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum
# 6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJ
# aISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWojayL/
# ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDCCBq4wggSWoAMCAQIC
# EAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIyMDMyMzAw
# MDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQw
# OTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2
# EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuA
# hIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1decfBmWNlCnT2exp39mQ
# h0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFobjchu0CsX7Le
# Sn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw5
# 4qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP2
# 9p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlRErWHRAKKtzQ87fSqEcazjF
# KfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHt
# Qr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh3pP+OcD5sjClTNfpmEpY
# PtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4J
# duyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnSDmuZDNIztM2xAgMBAAGj
# ggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2
# mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBp
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUH
# MAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRS
# b290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EM
# AQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIB
# fmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb
# 122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+r
# T4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2dfNBwCnzvqLx1T7pa96kQ
# sl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibBt94q6/aesXmZgaNWhqsK
# RcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7T6NJuXdmkfFynOlLAlKn
# N36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSe
# reU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no
# 8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcW
# oWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInw
# AM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7
# qS9EFUrnEw4d2zc4GqEr9u3WfPwwggbAMIIEqKADAgECAhAMTWlyS5T6PCpKPSkH
# gD1aMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2
# IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjIwOTIxMDAwMDAwWhcNMzMxMTIx
# MjM1OTU5WjBGMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxJDAiBgNV
# BAMTG0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIyIC0gMjCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAM/spSY6xqnya7uNwQ2a26HoFIV0MxomrNAcVR4eNm28
# klUMYfSdCXc9FZYIL2tkpP0GgxbXkZI4HDEClvtysZc6Va8z7GGK6aYo25BjXL2J
# U+A6LYyHQq4mpOS7eHi5ehbhVsbAumRTuyoW51BIu4hpDIjG8b7gL307scpTjUCD
# HufLckkoHkyAHoVW54Xt8mG8qjoHffarbuVm3eJc9S/tjdRNlYRo44DLannR0hCR
# RinrPibytIzNTLlmyLuqUDgN5YyUXRlav/V7QG5vFqianJVHhoV5PgxeZowaCiS+
# nKrSnLb3T254xCg/oxwPUAY3ugjZNaa1Htp4WB056PhMkRCWfk3h3cKtpX74LRsf
# 7CtGGKMZ9jn39cFPcS6JAxGiS7uYv/pP5Hs27wZE5FX/NurlfDHn88JSxOYWe1p+
# pSVz28BqmSEtY+VZ9U0vkB8nt9KrFOU4ZodRCGv7U0M50GT6Vs/g9ArmFG1keLuY
# /ZTDcyHzL8IuINeBrNPxB9ThvdldS24xlCmL5kGkZZTAWOXlLimQprdhZPrZIGwY
# UWC6poEPCSVT8b876asHDmoHOWIZydaFfxPZjXnPYsXs4Xu5zGcTB5rBeO3GiMiw
# bjJ5xwtZg43G7vUsfHuOy2SJ8bHEuOdTXl9V0n0ZKVkDTvpd6kVzHIR+187i1Dp3
# AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgB
# hv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8wHQYDVR0OBBYE
# FGKK3tBh/I8xFO2XC809KpQU31KcMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9j
# cmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZU
# aW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKGTGh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEy
# NTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAFWqKhrzRvN4
# Vzcw/HXjT9aFI/H8+ZU5myXm93KKmMN31GT8Ffs2wklRLHiIY1UJRjkA/GnUypsp
# +6M/wMkAmxMdsJiJ3HjyzXyFzVOdr2LiYWajFCpFh0qYQitQ/Bu1nggwCfrkLdcJ
# iXn5CeaIzn0buGqim8FTYAnoo7id160fHLjsmEHw9g6A++T/350Qp+sAul9Kjxo6
# UrTqvwlJFTU2WZoPVNKyG39+XgmtdlSKdG3K0gVnK3br/5iyJpU4GYhEFOUKWaJr
# 5yI+RCHSPxzAm+18SLLYkgyRTzxmlK9dAlPrnuKe5NMfhgFknADC6Vp0dQ094XmI
# vxwBl8kZI4DXNlpflhaxYwzGRkA7zl011Fk+Q5oYrsPJy8P7mxNfarXH4PMFw1nf
# J2Ir3kHJU7n/NBBn9iYymHv+XEKUgZSCnawKi8ZLFUrTmJBFYDOA4CPe+AOk9kVH
# 5c64A0JH6EE2cXet/aLol3ROLtoeHYxayB6a1cLwxiKoT5u92ByaUcQvmvZfpyeX
# upYuhVfAYOd4Vn9q78KVmksRAsiCnMkaBXy6cbVOepls9Oie1FqYyJ+/jbsYXEP1
# 0Cro4mLueATbvdH7WwqocH7wl4R44wgDXUcsY6glOJcB0j862uXl9uab3H4szP8X
# TE0AotjWAQ64i+7m4HJViSwnGWH2dwGMMYIF6TCCBeUCAQEwJDAQMQ4wDAYDVQQD
# DAVKME43RQIQJTSMe3EEUZZAAWO1zNUfWTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGC
# NwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU0tkFZcPh
# N/yzoSEdjugLOWKf4nowDQYJKoZIhvcNAQEBBQAEggIAhzS+uWytnUptQpeHokXn
# VgVpvJqg5KYprQBmLV5nX6ZnYxIwgqcR09Q5Kyzx0UKKbCssG+oZ/JzIvRcUPHHU
# 7sor/CoylhH62jlqC5L3LagAzeHOxu7jTxASxgw2qt/80siNXGCIL0Y8fc3vt0s0
# 4Xo4cbIEINLn0AHX+5MpMsjcIeSX0yT78iz0qRE0+Pe96g6uCXsxFnKnZsJ8V5OC
# zn+ZjsmocI+UmWMZtcuyIYUNZBXt4rPJimKMu/8nKZj7N8lxsjax/gwwO44PqUJ+
# 4463DvxnNRXoyRu1U2GAX3qV+WtIQmfSfpfYuzkchnWjB3JVNtlFn2gRz0ArBmYR
# k8MqJPg5pOlu9HgRuRXQVd1MhWkReEKro7XikLo1W/bvgo0KHxxddUs0d7meT8PA
# jghrBElMgpe1+svf5aTljHVvRzx4xmwmPDNxVZjGkeaYJl7IUp/jlT/9BBGF25r8
# 9XegJvHDnKq8xlZuXu9qQR3guCfW5HV1Pvp2odElBRDZfA9EVt5vdIP/B4FAlI3a
# 4rqM7/QmatXG02+gP5FokM0PfHbR/be5jcguaWZ5ui9u8fTUgnMVwTejB7netKHr
# /IngAuBlRr/ZxBihi/jUQX53ZAUQ/HvA40pEM0LWkVfVDf7WJ42xMgI0V860NcC+
# lvYzzVfkEsJCasqlZcNokwShggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEw
# dzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNV
# BAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1w
# aW5nIENBAhAMTWlyS5T6PCpKPSkHgD1aMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjMwNDA3MDAwMDA0
# WjAvBgkqhkiG9w0BCQQxIgQgIMc5fBa3BYLqvQo7AvNgOh/CVc/WF9dgY3B0P98t
# 26YwDQYJKoZIhvcNAQEBBQAEggIAjiEmeTrXjg+pGr5SA+IEdgmszqVdt90Q6xi6
# kyWnCnfpIsOuwU0LFmknvOKaF2ASb8DxnQ/ZKiUxG9jWSu4X5rf4ie60+8SizWlk
# NXNX1kAubB1kBqH2I84gY1rsohXH2QTIQjf7vkVX16RgYqRqfwLXBeq21d4haEGF
# jakW4OfULcJp7FJtnjTIuARVGaNRymHMgGm4XhVHECs8YiYrT5aD9VUUJYSVn428
# hoUrIjfddtM0OPT7B/u5KkKGp/rTB5DnS5h/vPeHf3u5uOa3vwlnw+CL7IUVDZjY
# eDaIMCR/Wt5lhKpAx6Acp6qT56QEyKkD9QEuDIMiJPMU8LdDAIvOvw3wsnqwpyYK
# wCgWhuxZkNsxgbGV943+BAasjmHupT7NT3Bcboe36K/t6/bnV5kUq0l6gXHPlklJ
# w7kdTczJu5JO21mkAPPA+gWBtSJg15n26BVp/7kIfEHDbqWTKu8DAS+coBWf2DY2
# XvW7IORPH8CQhWq9AxgpmTRyqrgAkpHBoMa6GbY0VdvARUQI6m98h8PT8IcV9PCs
# ZrwKVj5XgAeX3Fp/mxfuN7t8Mjgv4lXUi+W3Rgb77XUQSTI51Pe7hjn7qPl+JFD2
# D8B2yPMerQJqqh6WyFhtiJ7xK8PhdNY6ZjFse8+IB1KMtt2VR1HLdgG8BLOWZrg3
# tk/hiU8=
# SIG # End signature block
