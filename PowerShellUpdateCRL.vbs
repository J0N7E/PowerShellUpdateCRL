
set shell = CreateObject("WScript.Shell")
shell.Run "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy RemoteSigned -NonInteractive -NoProfile -File .\PowerShellUpdateCRL.ps1", 0

