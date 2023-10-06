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
        $Now = Get-Date

        if ($Now -ge $Cert.NotBefore -and $Now -le $Cert.NotAfter)
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
    }

    #######
    # Exec
    #######

    foreach($Cdp in $CdpHashtable.GetEnumerator())
    {
        # Get cdp header
        $Head = Try-WebRequest -Uri "$($Cdp.Value.Url)" -Method Head

        Write-Verbose -Verbose -Message "URL=$($Cdp.Value.Url)"

        # Header request successfull
        if ($Head -and $Head.StatusCode -eq '200')
        {
            # Get etag from header
            $ETag = $Head.Headers["ETag"] | Where-Object { $_ -match '"(.*):0"' } | ForEach-Object { $Matches[1] }

            Write-Verbose -Verbose -Message "ETag=$ETag"

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
# MIIekwYJKoZIhvcNAQcCoIIehDCCHoACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUL6RqUJ+SifM665P3n0SLcnnq
# SeqgghgUMIIFBzCCAu+gAwIBAgIQdFzLNL2pfZhJwaOXpCuimDANBgkqhkiG9w0B
# AQsFADAQMQ4wDAYDVQQDDAVKME43RTAeFw0yMzA5MDcxODU5NDVaFw0yODA5MDcx
# OTA5NDRaMBAxDjAMBgNVBAMMBUowTjdFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEA0cNYCTtcJ6XUSG6laNYH7JzFfJMTiQafxQ1dV8cjdJ4ysJXAOs8r
# nYot9wKl2FlKI6eMT6F8wRpFbqKqmTpElxzM+fzknD933uEBLSAul/b0kLlr6PY2
# oodJC20VBAUxthFUYh7Fcni0dwz4EjXJGxieeDDLZYRT3IR6PzewaWhq1LXY3fhe
# fYQ1Q2nqHulVWD1WgucgIFEfUJCWcOvfmJBE+EvkNPVoKAqFxJ61Z54z8y6tIjdK
# 3Ujq4bgROQqLsFMK+mII1OqcLRKMgWkVIS9nHfFFy81VIMvfgaOpoSVLatboxAnO
# mn8dusJA2DMH6OL03SIBb/FwE7671sjtGuGRp+nlPnkvoVqFET9olZWDxlGOeeRd
# Tc3jlcEPb9XLpiGjlQfMfk4ycSwraJqn1cYDvSXh3K6lv0OeSLa/VQRlEpOmttKB
# EI/eFMK76DZpGxFvv1xOg1ph3+01hCboOXePu9qSNk5hnIrBEb9eqks3r5ZDfrlE
# wjFUhd9kLe2UKEaHK7HI9+3x1WhTgNRKWzKzqUcF9aVlpDQRplqbUMJEzMxzRUIk
# 01NDqw46gjUYet6VnIPqnQAe2bLWqDMeL3X6P7cAHxw05yONN51MqyBFdYC1MieY
# uU4MOoIfIN6M6vEGn7avjw9a4Xpfgchtty2eNgIRg+KuJ3Xxtd1RDjUCAwEAAaNd
# MFswDgYDVR0PAQH/BAQDAgWgMCoGA1UdJQQjMCEGCCsGAQUFBwMDBgkrBgEEAYI3
# UAEGCisGAQQBgjcKAwQwHQYDVR0OBBYEFFjQBHg94o+OtZeRxQoH0mKFzMApMA0G
# CSqGSIb3DQEBCwUAA4ICAQBSglLs0PCn7g36iGRvqXng/fq+6nL3ZSLeLUXSDoFX
# KhJ3K6wFSiHBJtBYtWc7OnHIbIg1FFFAi5GIP56MMwmN4NoY0DrBN0Glh4Jq/lhu
# iah5zs/9v/aUvtwvBD4NVX0G/wJuRuX697UQZrtkWninB46BMPU+gEg1ctn0V4zQ
# 3fazrcmJqD9xIwKlOXsvxOAO5OJ51ucdsubD6QkJa++4bGd5HhoC8/O18mxz6YYa
# gOnXWJObybkwdkDC9MUjy5wZNAv48DkUM+OArbfM3ZpfcAVTnDrfuzpoOKTkcdgb
# N+4VXJC/ly1D98f+IpEOw1UItX8Hg67WfU9sXcIY+fghzHPHF864vp2F/G75i02M
# oqeRpeO3guwum3DbKCkKts5S1QXnE7pmeqe4U595jCVhELeB6ifrvj0ulSlOU5GE
# twNY5VL0T3cHegBmtQXFfQoT6vboF6m9I7kVlKGT4WI8M/UQYCQ2ZP3HTjdSHt9U
# cJslGMqDxhbkGLH49ESP5ghbRddll24dsw0dF96lOIEmhB01UNIz40TonraK3cku
# Jdnrh/2fHYbycGHjkowiMUJQaihbZBRKvBHhrM7OuQ96M9g8Gk2RCIqdX0lO8n2y
# S8fnzEoWe8FVwE5bgA5Nwl6iYdoszubYgh+siVMe2EFaUh0DXXpbQ3JxjMGe5qVK
# 1zCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAw
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
# qS9EFUrnEw4d2zc4GqEr9u3WfPwwggbCMIIEqqADAgECAhAFRK/zlJ0IOaa/2z9f
# 5WEWMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2
# IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjMwNzE0MDAwMDAwWhcNMzQxMDEz
# MjM1OTU5WjBIMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# IDAeBgNVBAMTF0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIzMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAo1NFhx2DjlusPlSzI+DPn9fl0uddoQ4J3C9Io5d6
# OyqcZ9xiFVjBqZMRp82qsmrdECmKHmJjadNYnDVxvzqX65RQjxwg6seaOy+WZuNp
# 52n+W8PWKyAcwZeUtKVQgfLPywemMGjKg0La/H8JJJSkghraarrYO8pd3hkYhftF
# 6g1hbJ3+cV7EBpo88MUueQ8bZlLjyNY+X9pD04T10Mf2SC1eRXWWdf7dEKEbg8G4
# 5lKVtUfXeCk5a+B4WZfjRCtK1ZXO7wgX6oJkTf8j48qG7rSkIWRw69XloNpjsy7p
# Be6q9iT1HbybHLK3X9/w7nZ9MZllR1WdSiQvrCuXvp/k/XtzPjLuUjT71Lvr1KAs
# NJvj3m5kGQc3AZEPHLVRzapMZoOIaGK7vEEbeBlt5NkP4FhB+9ixLOFRr7StFQYU
# 6mIIE9NpHnxkTZ0P387RXoyqq1AVybPKvNfEO2hEo6U7Qv1zfe7dCv95NBB+plwK
# WEwAPoVpdceDZNZ1zY8SdlalJPrXxGshuugfNJgvOuprAbD3+yqG7HtSOKmYCaFx
# smxxrz64b5bV4RAT/mFHCoz+8LbH1cfebCTwv0KCyqBxPZySkwS0aXAnDU+3tTbR
# yV8IpHCj7ArxES5k4MsiK8rxKBMhSVF+BmbTO77665E42FEHypS34lCh8zrTioPL
# QHsCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYG
# A1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCG
# SAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4E
# FgQUpbbvE+fvzdBkodVWqWUxo97V40kwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDov
# L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1
# NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNI
# QTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAgRrW3qCp
# tZgXvHCNT4o8aJzYJf/LLOTN6l0ikuyMIgKpuM+AqNnn48XtJoKKcS8Y3U623mzX
# 4WCcK+3tPUiOuGu6fF29wmE3aEl3o+uQqhLXJ4Xzjh6S2sJAOJ9dyKAuJXglnSoF
# eoQpmLZXeY/bJlYrsPOnvTcM2Jh2T1a5UsK2nTipgedtQVyMadG5K8TGe8+c+nji
# kxp2oml101DkRBK+IA2eqUTQ+OVJdwhaIcW0z5iVGlS6ubzBaRm6zxbygzc0brBB
# Jt3eWpdPM43UjXd9dUWhpVgmagNF3tlQtVCMr1a9TMXhRsUo063nQwBw3syYnhmJ
# A+rUkTfvTVLzyWAhxFZH7doRS4wyw4jmWOK22z75X7BC1o/jF5HRqsBV44a/rCcs
# QdCaM0qoNtS5cpZ+l3k4SF/Kwtw9Mt911jZnWon49qfH5U81PAC9vpwqbHkB3NpE
# 5jreODsHXjlY9HxzMVWggBHLFAx+rrz+pOt5Zapo1iLKO+uagjVXKBbLafIymrLS
# 2Dq4sUaGa7oX/cR3bBVsrquvczroSUa31X/MtjjA2Owc9bahuEMs305MfR5ocMB3
# CtQC4Fxguyj/OOVSWtasFyIjTvTs0xf7UGv/B3cfcZdEQcm4RtNsMnxYL2dHZeUb
# c7aZ+WssBkbvQR7w8F/g29mtkIBEr4AQQYoxggXpMIIF5QIBATAkMBAxDjAMBgNV
# BAMMBUowTjdFAhB0XMs0val9mEnBo5ekK6KYMAkGBSsOAwIaBQCgeDAYBgorBgEE
# AYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwG
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQUMY27
# ibf7zUqE2AVqSqKdo9pcUDANBgkqhkiG9w0BAQEFAASCAgB7hU2dlOKDj/al6c/7
# UX4VP0tIVoGAFADWvUpi25r+umyS/6CyBT92kKyTDKD2HMebn16UMWUI97Sl4js7
# iCvuCtfPDzX6AZO+6cXG1a+5bybDYQ9A7EqR6T7TLLIlfeVBH/6JgKTHBrfvmpT7
# wcdU4FsprRjd7vvtVurhoLqVddeYe1VKEQCB54hfxqNzXk/5lrCGz/s3XSRnQgNM
# pp8wBvF4LtkHy1RR+X+9LZ20qD0ejw6ORt6EBpBXaUd8PeHRz6CIxQzBruUXoNWT
# xJvOwLA88pzkGGXR+63rPcdaB2KmG05F5ADUSvI/ecB+74XAp/mgLAF2bcWpgele
# 2fWov/O/ve3svsAYTEhPRgwyc3F62Xz+8xLM/EnOQddOIyKxmxjSefL1M9wR96Bu
# v6WCJHOVnt+mC3yNyUGLzuyopS3f8Td4OaHO8TixiSjxswN4bqekfje6mbzjdt7g
# 0GkyQRF19TEtqBQwERA4pm8GG3wuZmpFNyarYObVlK0pPQgt03mpBRucW0kOGTvN
# oFTqWVbEa8wpzitiCcocKEaUB8DcLxHTcg/NWO2zOi57F2hWYdDTKeX3rL2LHA62
# w+ODC2cZciZusM3ncOCna7u6R+zZuIfEn1o5cnKvkNeUV1460A+J/sCFkp3wIzPc
# CU1UltA1mCU13bc282LoeSsL0qGCAyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIB
# ATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/lYRYwDQYJYIZIAWUDBAIBBQCgaTAYBgkq
# hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMzEwMDYwOTAw
# MDVaMC8GCSqGSIb3DQEJBDEiBCA1T9XQHI1qpCTiW6EhUjbZ7krOFEWF00MNO3aD
# 2Kw9BDANBgkqhkiG9w0BAQEFAASCAgAmNy6cjiQJZvODoETKx9ogB43oiPQLJ7tB
# L26KGxazqsXJOMyaxIce7kOqpKI3lATqBVmBItFXKtCsmt5WiQ7rGWToUPa5IAeu
# an6+TWQxxZVOxAGXldS+AXOf4/RqfWnU4+xXeQq6EciG4F8otD3U4WO0uyLqerp9
# asqMsJ8Rk3IUzOSVpZw98CR7HCRWAKhkLuAiwAxqwRVY2m1UFi+3e81Uc3GvmWO7
# JyrVkTUj/30+nsezRfG1e156iomA4XxtkJN3QMHJ9ZWZt21ByUOZV7ZPn7X9fIHi
# 4oBvLlXhDlgLwYOVXhp3xJ5ujqhrWXWpc9OLh9n5shQQbt6IsXqKeIK4TG3XQPST
# m1/q3dRdyNQ0tFZQz7y9TcSOPXPw+BfgiFoIPvZ2ehvtcKE+qTFSJ0T86EOunays
# ZzZROaP7QZNjsf3yTx+4szrBeT78VNUGGoE2ELYDlh6mMc0lqyCVP/vD4Dtf5snp
# SiGjE02y+Lkny8r9zW+Lq0MArj1TpdCHNAmybSRYaiOpnI5tI+GrvtB2MkHcrOrd
# ANR40eBn6H4JipVASwr2+QHbgloAZzNOPb2lz6C+4uhxQK6DYMhc5EXqn3i642Ep
# aojA2MIb/ytIpKYdtdUkbfjx1CEQrHijR5tQv0ZRFyXrG1PHLgbz33fSMVR84uVH
# GhgClyavmQ==
# SIG # End signature block
