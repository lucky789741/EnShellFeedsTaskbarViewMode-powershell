param($option)

if($option -lt 0 -or $option -gt 2) {
    Write-Host 'Invalid option'
    Write-Host '2 for off, 1 for icon only, 0 for on'
    return 1
}
#HashData function
$MethodDefinition = @’

[DllImport("Shlwapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = false)]
   public static extern int HashData(
    byte[] pbData,
    int cbData,
    byte[] piet,
   int outputLen);

‘@
$Shlwapi = Add-Type -MemberDefinition $MethodDefinition -Name ‘Shlwapi’ -Namespace ‘Win32’ -PassThru
#machineId Registry Value
$machineIdReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\SQMClient\' -Name 'MachineId' -ErrorAction SilentlyContinue
$machineId = '{C283D224-5CAD-4502-95F0-2569E4C85074}' #Fallback Value
if($machineIdReg) {
    $machineId = $machineIdReg.MachineId
}
#replicate the algorithm in explorer.exe
$combined = $machineId+'_'+$option.ToString()
$reverse = $combined[($combined.Length-1)..0] -join ''
$bytesIn = [system.Text.Encoding]::Unicode.GetBytes($reverse)
$bytesOut = [byte[]]::new(4)
$hr = $Shlwapi::HashData($bytesIn,0x53, $bytesOut, $bytesOut.Count)
if(0 -ne $hr) {
    Write-Host 'HashData failed'
    return 2
}
$dwordData = [System.BitConverter]::ToUInt32($bytesOut,0)
#prevent driver block using rename method
#random name reduce chances of collision
$randStr = (0x0..0xF | Get-Random -Count 8 | foreach {$_.ToString('X')}) -join ''
$originalReg = Get-Command reg
$newName = $originalReg.Name.Replace($originalReg.Extension,'')
$newName += $randStr
$newName += $originalReg.Extension
$newNameFull = "$PSScriptRoot\$newName"
$ret = Copy-Item $originalReg.Source $newNameFull -PassThru -ErrorAction SilentlyContinue
if(!$ret) {
    Write-Host 'Copy-Item failed'
    return
}
#set ShellFeedsTaskbarViewMode
$ret = Start-Process -NoNewWindow -Wait -FilePath $newNameFull -ArgumentList 'ADD','HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds\','/v','ShellFeedsTaskbarViewMode','/t','REG_DWORD','/d',$option,'/f' -PassThru -ErrorAction SilentlyContinue
if(!$ret -or 0 -ne $ret.ExitCode) {
    Write-Host 'Registry Set ShellFeedsTaskbarViewMode Failed'
    return
}
#set EnShellFeedsTaskbarViewMode
$ret = Start-Process -NoNewWindow -Wait -FilePath $newNameFull -ArgumentList 'ADD','HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds\','/v','EnShellFeedsTaskbarViewMode','/t','REG_DWORD','/d',$dwordData,'/f' -PassThru -ErrorAction SilentlyContinue
if(!$ret -or 0 -ne $ret.ExitCode) {
    Write-Host 'Registry Set EnShellFeedsTaskbarViewMode Failed'
    return
}
Remove-Item $newNameFull -Force -Confirm:$false