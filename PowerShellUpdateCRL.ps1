<#
 .SYNOPSIS
    PowerShell Update CRL

 .DESCRIPTION
    Itterate certificates for CDP and AIA extensions
    Download CRL from distribution point, if successful and new crl exist, remove cache

 .NOTES
    AUTHOR Jonas Henriksson
    CREDIT TO Vadims Podāns for ASN.1 functions

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
        [System.Diagnostics.EventLog]::SourceExists($EventSource)

        #Check which log registered event source is registered under
        [System.Diagnostics.EventLog]::LogNameFromSourceName($EventSource,'.')

        #Remove registered event with:
        #[System.Diagnostics.EventLog]::DeleteEventSource($EventSource)
    }
#>

try
{
    #######
    # Init
    #######

    $CdpEntries = @{}
    $NonInteractive = [Environment]::GetCommandLineArgs() | Where-Object { $_ -eq '-NonInteractive' }

    #######
    # Func
    #######

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

    # https://social.technet.microsoft.com/Forums/windows/en-US/e86bdf17-8902-4f74-b5d4-7ca60b99e185/ocsp-issues
    function Get-ASN1Length
    {
        param
        (
            [Array]$RawData,
            [Int]$Offset
        )

        if ($RawData[$offset + 1] -lt 128) {
          $return.lengthbytes = 1
          $return.Padding = 0
          $return.PayLoadLength = $RawData[$offset + 1]
          $return.FullLength = $return.Padding + $return.lengthbytes + $return.PayLoadLength + 1
        } else {
          $return.lengthbytes = $RawData[$offset + 1] - 128
          $return.Padding = 1
          $lengthstring = -join ($RawData[($offset + 2)..($offset + 1 + $return.lengthbytes)] | %{"{0:x2}" -f $_})
          $return.PayLoadLength = Invoke-Expression 0x$($lengthstring)
          $return.FullLength = $return.Padding + $return.lengthbytes + $return.PayLoadLength + 1
        }

        $return = "" | Select FullLength, Padding, LengthBytes, PayLoadLength
    $return
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
        # Decode CDP extension
        $CdpUrl = (New-Object System.Security.Cryptography.AsnEncodedData(
            '2.5.29.31',
            $Cert.Extensions['2.5.29.31'].RawData

        # Get CDP URL
        )).Format($false) | Where-Object { $_ -match 'URL=(.*?)(?=$|\s\()' } | ForEach-Object { $Matches[1] }

        if (-not $CdpEntries.Contains("$CdpUrl"))
        {
            # Get issuer CN
            $Issuer = $Cert.Issuer | Where-Object { $_ -match 'CN=(.*?)(?:,|$)' } | ForEach-Object { $Matches[1] }

            $CdpEntries.Add("$CdpUrl", "$Issuer")
        }
    }

    #######
    # Exec
    #######

    foreach($CdpUrl in $CdpEntries.GetEnumerator())
    {
        # Get cdp header
        $Head = Try-WebRequest -Uri "$($CdpUrl.Name)" -Method Head

        # Header request successfull
        if ($Head -and $Head.StatusCode -eq '200')
        {
            # Get etag from header
            $ETag = $Head.Headers["ETag"] | Where-Object { $_ -match '"(.*):0"' } | ForEach-Object { $Matches[1] }

            # Get old etag
            $OldETag = [System.Environment]::GetEnvironmentVariable("$($CdpUrl.Value)_ETag", 'User')

            # Check if to download crl
            if(-not $ETag -or $ETag -ne $OldETag)
            {
                # Request crl
                $Request = Try-WebRequest -Uri "$($CdpUrl.Name)"

                # Request successfull
                if($Request -and $Request.StatusCode -eq '200')
                {
                    # Get filename
                    $CdpFile = $CdpUrl.Name.Substring($CdpUrl.Name.LastIndexOf('/') + 1)

                    # Save crl to temp
                    Set-Content -Value $Request.Content -LiteralPath "$env:TEMP\$CdpFile" -Encoding Byte

                    if(-not $ETag)
                    {
                        # Initialize
                        $OldCRLNumber = $null

                        # Check old and new crl
                        foreach ($Arg in "-store ca `"$($CdpUrl.Value)`"", "`"$env:TEMP\$CdpFile`"")
                        {
                            # Get crl number
                            $CRLNumber = Invoke-Expression -Command "certutil $Arg" | Where-Object { $_ -match 'CRL Number=(.*)$' } | ForEach-Object { $Matches[1] }

                            if (-not $CRLNumber)
                            {
                                $CRLNumber = 0
                            }

                            # Convert from hex
                            $CRLNumber = [uint32] "0x$CRLNumber"

                            # Set old crl number
                            if (-not $OldCRLNumber)
                            {
                                $OldCRLNumber = $CRLNumber
                            }
                        }
                    }

                    if($ETag -or $CRLNumber -gt $OldCRLNumber)
                    {
                        # Remove old crl
                        certutil -delstore ca "$($CdpUrl.Value)" > $null

                        Write-Log -EntryType Information -Message "Updating CRL `"$CdpFile`" for $(whoami)"
                        certutil -addstore ca "$env:TEMP\$CdpFile" > $null

                        # Remove crl cache
                        certutil -urlcache "$([Uri]::EscapeUriString($CdpUrl.Name))" delete > $null

                        # Remove oscp cache
                        #certutil -urlcache "$OcspRequest" delete > $null

                        if($ETag)
                        {
                            # Remember etag
                            [System.Environment]::SetEnvironmentVariable("$($CdpUrl.Value)_ETag", $ETag, 'User')
                        }
                    }
                }
            }
        }
    }
}
catch [Exception]
{
    Write-Log -EntryType Error -Message $_
}

# SIG # Begin signature block
# MIIekQYJKoZIhvcNAQcCoIIegjCCHn4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUyIAd0UfuMmKj79XL8XZA1OlT
# 4hCgghgSMIIFBzCCAu+gAwIBAgIQJTSMe3EEUZZAAWO1zNUfWTANBgkqhkiG9w0B
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUAlecqLHl
# HViPEnotGFDANMbQwgkwDQYJKoZIhvcNAQEBBQAEggIAY0ecR6IBcyZVHE0VUbxx
# EpY4xjAR0RXoAlvwOI5k6vAyr4k5L9vbq/rRome+/V/jiDNjWqkl/Vo7OTiKdM/X
# 6mk6XZReizmX7fdK6zZGR5jLyQsiwvyyATBeBqNLjCJF6lUgnJjVMhXkr7Q7gWLk
# H+YZaGOVkzCY64XZXEjEySYu0rOHUCKkJgTUnnCxfKU7ECjCsN5uI1HGcQLDMs34
# o4B5c0mVgxDKT4YMtTSTUYQjPEOTcvfsdu9o0Dcx2epw8ef9i9Cwg8qJFuoa2ahH
# Ep9SbqgwokpA56nFsycPR1YQC3zUuI5FUEdO+qOvpsNIbtA8S0usypuBRWBbgnhm
# ui6XbuzAk13q1glatYvslT+Q2Du7ttewhs5OoAqxjuI/LFkdjPI99G0NDq0XP3gx
# iJzuSoXY+ieD11KeXxcyHir8xlCIYzPnSEvNjlW07/QPNTcqCHu//7edZ8Eb50dr
# SSsPghcMyDcsZ2ASblhNlphaX7Sq0newoAJtiSkOUUOigJrbQFJz3Le1WXjJO5X7
# L7mwUFGjprvtA+Zv3JVWI8VjHvGLDsx09kEtKdO93GaoCFONHddl80vQgo6t7j2y
# KgF1ND90nUtafEPGA9wMAn8OGg2VUBJlGuuBzDbJklqRkDfqAYPufYX6/E9+bme4
# WUa6wrBXroVeAybNaHz7qyOhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEw
# dzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNV
# BAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1w
# aW5nIENBAhAMTWlyS5T6PCpKPSkHgD1aMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjMwNDA0MTIwMDA2
# WjAvBgkqhkiG9w0BCQQxIgQgZsH5Tu6I4AsN7egrQgVCMJvTqmLKF+9NO4E2KA5B
# 3QkwDQYJKoZIhvcNAQEBBQAEggIAPWmmjHUxQnNICjaFeUeUcbZT8QkYwpa5Isat
# nUnASST7YVgReL/fzoId6h/02YMWJB4lac7CPLX0mCgwdsYWWX4dxc44YfrJWTXS
# I/0wsJFi/RKMbuX9HUrtLNx4Uy3HxGTzdtHoMo1dPQQnFWIp5sdT/sF9Uz2Fqe7a
# 2z9queQRlENvimMI2SMxz5VRPhBJ88HE34D+ALvdoOSjmG137cik1XAbnoJJnxHg
# 0ATerrpIt1UShpFbw6TFBRGSzjD4qo8IFWXl4tbVXL0Zrhewy2o2TsUsnnSZgy5J
# QJS4thfNzbioyoTuidSIyWz9ulNAVlbG69YqlGGXwo0cg+wuizntttDXd8kiNMho
# aWPAKb+w+yux1VUAWx3ERibaxpaYRnJY+XH1BSnKNEZM0RhjbMYhN3GsOYnr3WF4
# InmqYUEjCsFHgKoTuiLAD7X/mFVs+GG6EJEuruLOg2LBbp+63ThyD26B2JMXMRU7
# ajNnH9coalPhhNN1ItxkxOLdampjnZJx23eFi7D4JzKZLKMgodJgy02pmSpIJypL
# j1uTRiqhu0RwPIQ05Q1xdvWZlm3RUklhGCcXPAFF5Px+C48UvGiY4LMUn2lt5Bir
# +s8cxUi/rBpKfK+TbT3QU/reV8IVvWNLEfHu+xFELwL6TLLFUVMOKImhud6JVC/T
# lE4MAPI=
# SIG # End signature block
