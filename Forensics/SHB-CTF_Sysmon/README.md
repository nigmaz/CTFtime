# SHB-CTF_Sysmon

> Challenge: Sysmon

![Sysmon.png](./images/Sysmon.png)

```ps1
SCHTASKS  /Create /S localhost /RU DOMAIN\user /RP At0micStrong /TN " Atomic "task /TR C:\windows\system32\cmd.exe /SC daily /ST 20:10
```


