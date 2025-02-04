# AD-Tools
List of some AD tools I frequently use
## List Of Tools
- netexec (https://www.netexec.wiki/getting-started/installation/installation-on-unix)
- impacket (https://github.com/fortra/impacket)
- BloodHound (https://github.com/BloodHoundAD/BloodHound/releases)
- BloodHound.py (https://github.com/dirkjanm/BloodHound.py)
- bofhound (https://github.com/fortalice/bofhound)
- RustHound (https://github.com/NH-RED-TEAM/RustHound)
- bloodyAD (https://github.com/CravateRouge/bloodyAD)
- powerview.py (https://github.com/aniqfakhrul/powerview.py)
- Certipy (https://github.com/ly4k/Certipy)
- PKINITtools (https://github.com/dirkjanm/PKINITtools)
- targetedKerberoast (https://github.com/ShutdownRepo/targetedKerberoast)
- gssapi-abuse (https://github.com/CCob/gssapi-abuse)
- krbrelayx (https://github.com/dirkjanm/krbrelayx)
- ntdissector (https://github.com/synacktiv/ntdissector)
- sliver (https://github.com/BishopFox/sliver)
- Responder (https://github.com/SpiderLabs/Responder)
- pypykatz (https://github.com/skelsec/pypykatz)
- pywhisker (https://github.com/ShutdownRepo/pywhisker.git)
- SharpCollection (https://github.com/Flangvik/SharpCollection)
- PowerView (https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
- Powermad (https://github.com/Kevin-Robertson/Powermad)
- ntlm_theft (https://github.com/Greenwolf/ntlm_theft)
- hashgrab (https://github.com/xct/hashgrab)
- RunasCs (https://github.com/antonioCoco/RunasCs/releases)
- GodPotato (https://github.com/BeichenDream/GodPotato)
- PrintSpoofer (https://github.com/itm4n/PrintSpoofer)
- DeadPotato (https://github.com/lypd0/DeadPotato)
- proxychains4
- chisel (https://github.com/jpillora/chisel)
- ligolo-ng (https://github.com/nicocha30/ligolo-ng)
- nc64.exe (https://github.com/int0x33/nc.exe/)
- rcat (https://github.com/xct/rcat)
- ConPtyShell (https://github.com/antonioCoco/ConPtyShell)
- winpspy (https://github.com/xct/winpspy)
- winPEAS (https://github.com/peass-ng/PEASS-ng/releases/tag/20240922-a5703fe8)
- PrivescCheck (https://github.com/itm4n/PrivescCheck)
- LaZagne (https://github.com/AlessandroZ/LaZagne)
## Recommendations
- It is recommended to use `pipx` whenever possible for installing command-line python applications to keep them isolated.
- It is also recommended to use a python virtual environment when installing tools to avoid breaking system-wide packages.
```
➜  python3 -m venv venv
➜  source venv/bin/activate
(venv) ➜
# to exit the virtual env
(venv) ➜  deactivate
➜  
```
## Installation
### netexec
```
sudo apt install pipx git
```

```
➜  pipx ensurepath
/home/serioton/.local/bin is already in PATH.

⚠️  All pipx binary directories have been added to PATH. If you are sure you want to proceed, try again with the '--force' flag.

Otherwise pipx is ready to go! ✨ 🌟 
```

```
➜  pipx install git+https://github.com/Pennyw0rth/NetExec
  installed package netexec 1.2.0+99d4e49, installed using Python 3.10.12
  These apps are now globally available
    - NetExec
    - netexec
    - nxc
    - nxcdb
done! ✨ 🌟 ✨
```

```bash
➜  nxc --version
1.2.0 - ItsAlwaysDNS - 99d4e49
```
### impacket
```
➜  python3 -m pipx install impacket
  installed package impacket 0.12.0, installed using Python 3.10.12
  These apps are now globally available
...
done! ✨ 🌟 ✨
```
### BloodHound
```
➜  wget https://github.com/BloodHoundAD/BloodHound/releases/download/v4.3.1/BloodHound-linux-x64.zip
```

```
➜  unzip BloodHound-linux-x64.zip
```

```
➜  mv BloodHound-linux-x64 BloodHound
```

```
➜  ./BloodHound --disable-gpu-sandbox
```
Add this to the `~/.zshrc` file
```
alias bloodhound="~/tools/BloodHound/BloodHound --disable-gpu-sandbox"
```
### BloodHound.py
```
pipx install bloodhound
```

```
➜  bloodhound-python --help
usage: bloodhound-python [-h] [-c COLLECTIONMETHOD] [-d DOMAIN] [-v] [-u USERNAME] [-p PASSWORD] [-k] [--hashes HASHES] [-no-pass] [-aesKey hex key]
                         [--auth-method {auto,ntlm,kerberos}] [-ns NAMESERVER] [--dns-tcp] [--dns-timeout DNS_TIMEOUT] [-dc HOST] [-gc HOST] [-w WORKERS]
                         [--exclude-dcs] [--disable-pooling] [--disable-autogc] [--zip] [--computerfile COMPUTERFILE] [--cachefile CACHEFILE] [--use-ldaps]
                         [-op PREFIX_NAME]

Python based ingestor for BloodHound
For help or reporting issues, visit https://github.com/Fox-IT/BloodHound.py
```
### bofhound
```
pip3 install bofhound
```

```
➜  bofhound --help

 Usage: bofhound [OPTIONS]

 Generate BloodHound compatible JSON from logs written by ldapsearch BOF, pyldapsearch and Brute Ratel's LDAP Sentinel

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --input           -i      TEXT  Directory or file containing logs of ldapsearch results. Will default to /opt/bruteratel/logs if --brute-ratel is specified          │
│                                 [default: /opt/cobaltstrike/logs]                                                                                                    │
│ --output          -o      TEXT  Location to export bloodhound files [default: .]                                                                                     │
│ --all-properties  -a            Write all properties to BloodHound files (instead of only common properties)                                                         │
│ --brute-ratel                   Parse logs from Brute Ratel's LDAP Sentinel                                                                                          │
│ --debug                         Enable debug output                                                                                                                  │
│ --zip             -z            Compress the JSON output files into a zip archive                                                                                    │
│ --help                          Show this message and exit.                                                                                                          │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```
### RustHound
```
➜  git clone https://github.com/NH-RED-TEAM/RustHound.git
```

```
➜  curl https://sh.rustup.rs -sSf | sh
```

```
➜  cd RustHound
➜  RustHound git:(main) make install
```

```
➜  rusthound --help
---------------------------------------------------
Initializing RustHound at 14:22:01 on 09/23/24
Powered by g0h4n from OpenCyber
---------------------------------------------------

Active Directory data collector for BloodHound.
g0h4n <https://twitter.com/g0h4n_0>
```
### bloodyAD
```
➜  pip3 install bloodyAD
```

```
➜  bloodyAD
usage: bloodyAD [-h] [-d DOMAIN] [-u USERNAME] [-p PASSWORD] [-k] [-c CERTIFICATE] [-s] [--host HOST] [--dc-ip DC_IP] [--gc] [-v {QUIET,INFO,DEBUG}]
                {add,get,remove,set} ...

AD Privesc Swiss Army Knife
```
### powerview.py
```
➜  sudo apt install libkrb5-dev
➜  pip3 install powerview
```

```
➜  powerview
usage: powerview [-h] [-p PORT] [-d] [-q QUERY] [--use-system-nameserver | -ns NAMESERVER] [-v] [--use-ldap | --use-ldaps | --use-gc | --use-gc-ldaps]
                 [-H LMHASH:NTHASH] [-k | --use-channel-binding | --use-sign-and-seal | --simple-auth | --pfx PFX] [--no-pass] [--aes-key hex key]
                 [--dc-ip IP address] [--relay] [--relay-host RELAY_HOST] [--relay-port RELAY_PORT]
                 target

Python alternative to SharpSploit's PowerView script, version 2024.6.6
```
### certipy
```
➜  pip3 install certipy-ad
```
Or using pipx
```
➜  pipx install -f "git+https://github.com/ly4k/Certipy.git"
```

```
➜  certipy
Certipy v4.8.2 - by Oliver Lyak (ly4k)

usage: certipy [-v] [-h] {account,auth,ca,cert,find,forge,ptt,relay,req,shadow,template} ...

Active Directory Certificate Services enumeration and abuse
```
### PKINITtools
```
➜  git clone https://github.com/dirkjanm/PKINITtools
```
### targetedKerberoast
```
➜  git clone https://github.com/ShutdownRepo/targetedKerberoast
```
### gssapi-abuse
```
➜  git clone https://github.com/CCob/gssapi-abuse
```
### krbrelayx
```
➜  git clone https://github.com/dirkjanm/krbrelayx
```
### ntdissector
```
➜  git clone https://github.com/synacktiv/ntdissector
➜  python3 -m pip install ./ntdissector
```
### sliver
```
➜  wget https://github.com/BishopFox/sliver/releases/download/v1.5.42/sliver-server_linux -O sliver-server
➜  chmod +x sliver-server
➜  wget https://github.com/BishopFox/sliver/releases/download/v1.5.42/sliver-client_linux -O sliver-client
➜  chmod +x sliver-client
```
### Responder
```
➜  git clone https://github.com/SpiderLabs/Responder.git
➜  cd Responder
➜  Responder git:(master) python2 Responder.py --help
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 2.3

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CRTL-C

Usage: python Responder.py -I eth0 -w -r -f
or:
python Responder.py -I eth0 -wrf
```
### pypykatz
```
➜  pip3 install pypykatz
```
### pywhisker
```
➜  git clone https://github.com/ShutdownRepo/pywhisker.git
```
### SharpCollection
```
➜  git clone https://github.com/Flangvik/SharpCollection
```
### PowerView
```
➜  wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Recon/PowerView.ps1
```
### Powermad
```
➜  git clone https://github.com/Kevin-Robertson/Powermad.git
```
### ntlm_theft
```
➜  git clone https://github.com/Greenwolf/ntlm_theft
➜  cd ntlm_theft
➜  ntlm_theft git:(master) python3 ntlm_theft.py
usage: ntlm_theft.py --generate all --server <ip_of_smb_catcher_server> --filename <base_file_name>
ntlm_theft.py: error: the following arguments are required: -g/--generate, -s/--server, -f/--filename
```
### hashgrab
```
➜  git clone https://github.com/xct/hashgrab
➜  cd hashgrab
➜  hashgrab git:(main) python3 hashgrab.py
usage: hashgrab.py [-h] ip out
hashgrab.py: error: the following arguments are required: ip, out
```
### RunasCs
```
➜  wget https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip
➜  unzip RunasCs.zip
Archive:  RunasCs.zip
  inflating: RunasCs.exe
  inflating: RunasCs_net2.exe
```
### GodPotato
```
➜  wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe -O gp.exe
```
### PrintSpoofer
```
➜  wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
➜  wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer32.exe
```
### DeadPotato
```
➜  wget https://github.com/lypd0/DeadPotato/releases/download/v1.2/DeadPotato-NET4.exe
```
### proxychains
```
➜  sudo apt-get install proxychains4
```
### chisel
```
➜  wget https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_linux_amd64.gz
➜  gunzip chisel_1.10.0_linux_amd64.gz
➜  mv chisel_1.10.0_linux_amd64 chisel
➜  chmod +x chisel
```

```
➜  wget https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_windows_amd64.gz
➜  gunzip chisel_1.10.0_windows_amd64.gz
➜  mv chisel_1.10.0_windows_amd64 chisel.exe
```
### ligolo-ng
```
➜  wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.2-alpha/ligolo-ng_proxy_0.7.2-alpha_linux_amd64.tar.gz
➜  wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.2-alpha/ligolo-ng_agent_0.7.2-alpha_windows_amd64.zip
```

```
➜  tar xvf ligolo-ng_proxy_0.7.2-alpha_linux_amd64.tar.gz
LICENSE
README.md
proxy
➜  unzip ligolo-ng_agent_0.7.2-alpha_windows_amd64.zip
Archive:  ligolo-ng_agent_0.7.2-alpha_windows_amd64.zip
  inflating: LICENSE
  inflating: README.md
  inflating: agent.exe
```

```
➜  ls
agent.exe  proxy
```
### nc64.exe
```
➜  wget https://github.com/int0x33/nc.exe/raw/refs/heads/master/nc64.exe
```
### rcat
```
➜  git clone https://github.com/xct/rcat.git
➜  sudo apt update && sudo apt install mingw-w64
➜  cd rcat
➜  rcat git:(main) rustup target add x86_64-pc-windows-gnu
➜  rcat git:(main) rustup toolchain install stable-x86_64-pc-windows-gnu
➜  rcat git:(main) cargo build --release --target x86_64-pc-windows-gnu ### windows
➜  rcat git:(main) cargo build --release ### linux
➜  rcat git:(main) ls target/release/rcat
target/release/rcat
➜  rcat git:(main) ls target/x86_64-pc-windows-gnu/release/rcat.exe
target/x86_64-pc-windows-gnu/release/rcat.exe
```
### ConPtyShell
```
➜  wget https://github.com/antonioCoco/ConPtyShell/releases/download/1.5/ConPtyShell.zip
➜  wget https://raw.githubusercontent.com/antonioCoco/ConPtyShell/refs/heads/master/Invoke-ConPtyShell.ps1
```
### winpspy
```
➜  git clone https://github.com/xct/winpspy

Build with Visual Studio
```
### winPEAS
```
➜  wget https://github.com/peass-ng/PEASS-ng/releases/download/20240922-a5703fe8/winPEASx64.exe
```
### PrivescCheck
```
➜  wget https://raw.githubusercontent.com/itm4n/PrivescCheck/refs/heads/master/PrivescCheck.ps1
```
### LaZagne
```
➜  wget https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.6/LaZagne.exe
```
