# AD-Tools
List of some AD tools I frequently use

# Table of Contents
- [Recommendations](#recommendations)
- [Installation](#installation)
  - [NetExec](#netexec)
  - [Impacket](#impacket)
  - [bloodyAD](#bloodyad)
  - [Certipy](#certipy)
  - [PowerView.py](#powerviewpy)
  - [BloodHound](#bloodhound)
  - [BloodHound CE](#bloodhound-ce)
  - [BloodHound.py Legacy](#bloodhoundpy-legacy)
  - [BloodHound.py CE](#bloodhoundpy-ce)
  - [BOFHound](#bofhound)
  - [RustHound](#rusthound)
  - [RustHound-CE](#rusthound-ce)
  - [PKINITtools](#pkinittools)
  - [targetedKerberoast](#targetedkerberoast)
  - [gssapi-abuse](#gssapi-abuse)
  - [Krbrelayx](#krbrelayx)
  - [ntdissector](#ntdissector)
  - [pyWhisker](#pywhisker)
  - [PetitPotam](#petitpotam)
  - [pyGPOAbuse](#pygpoabuse)
  - [Responder](#responder)
  - [pypykatz](#pypykatz)
  - [SharpCollection](#sharpcollection)
  - [PowerView](#powerview)
  - [Powermad](#powermad)
  - [ntlm_theft](#ntlm_theft)
  - [Hashgrab](#hashgrab)
  - [Sliver](#sliver)
  - [RunasCs](#runascs)
  - [GodPotato](#godpotato)
  - [PrintSpoofer](#printspoofer)
  - [DeadPotato](#deadpotato)
  - [ProxyChains-NG](#proxychains-ng)
  - [Chisel](#chisel)
  - [Ligolo-ng](#ligolo-ng)
  - [nc64](#nc64)
  - [rcat](#rcat)
  - [ConPtyShell](#conptyshell)
  - [Winpspy](#winpspy)
  - [winPEAS](#winpeas)
  - [PrivescCheck](#privesccheck)
  - [LaZagne](#lazagne)
- [Resources](#resources)

## Recommendations
- It is recommended to use `pipx` or `uv` whenever possible for installing command-line python applications to keep them isolated.
- It is also recommended to use a python virtual environment when installing tools to avoid breaking system-wide packages.
```
$ python3 -m venv venv
$ source venv/bin/activate
(venv) $

# to exit the virtual env
(venv) $ deactivate
```
Installing pipx
```
$ sudo apt install pipx
$ pipx ensurepath
```
Installing [uv](https://docs.astral.sh/uv/getting-started/installation/)
```
$ curl -LsSf https://astral.sh/uv/install.sh | sh
```
or using pipx
```
$ pipx install uv
```
## Installation
### NetExec
```
$ sudo apt install pipx git
$ pipx ensurepath
$ pipx install git+https://github.com/Pennyw0rth/NetExec
```
Or
```
$ git clone https://github.com/Pennyw0rth/NetExec
$ cd NetExec
$ python3 -m pipx install .
```
### Impacket
```
$ python3 -m pipx install impacket
```
To install the dev version
```
$ git clone https://github.com/fortra/impacket
$ cd impacket
$ python3 -m pipx install .
```
### bloodyAD
```
$ pipx install bloodyAD
```
### Certipy
Using pip
```
$ python3 -m venv certipy-venv
$ source certipy-venv/bin/activate
$ pip install certipy-ad
```
Using pipx
```
$ pipx install -f "git+https://github.com/ly4k/Certipy.git"
```
### PowerView.py
```
$ sudo apt install libkrb5-dev
$ pipx install "git+https://github.com/aniqfakhrul/powerview.py"
```
### BloodHound
```
$ wget https://github.com/BloodHoundAD/BloodHound/releases/download/v4.3.1/BloodHound-linux-x64.zip
$ unzip BloodHound-linux-x64.zip
$ mv BloodHound-linux-x64 BloodHound
$ ./BloodHound --disable-gpu-sandbox
```
Add this alias to the `~/.zshrc` file
```
$ alias bloodhound="~/tools/BloodHound/BloodHound --disable-gpu-sandbox"
```
### BloodHound CE
```
$ wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
$ tar -xvzf bloodhound-cli-linux-amd64.tar.gz
$ ./bloodhound-cli install
```
### BloodHound.py Legacy
```
$ pipx install bloodhound
```
### BloodHound.py CE
```
$ pipx install bloodhound-ce
```
### BOFHound
```
$ pip3 install bofhound
```
### RustHound
First you need to install rust
```
$ curl https://sh.rustup.rs -sSf | sh
```
Then install RustHound
```
$ git clone https://github.com/NH-RED-TEAM/RustHound
$ cd RustHound
$ make install
```
### RustHound-CE
```
$ cargo install rusthound-ce
```
### PKINITtools
```
$ git clone https://github.com/dirkjanm/PKINITtools
$ cd PKINITtools
$ python3 -m venv venv
$ source ./venv/bin/activate
$ pip3 install -r requirements.txt
```
### targetedKerberoast
```
$ git clone https://github.com/ShutdownRepo/targetedKerberoast
$ cd targetedKerberoast
$ python3 -m venv venv
$ source ./venv/bin/activate
$ pip3 install -r requirements.txt
```
### gssapi-abuse
```
$ git clone https://github.com/CCob/gssapi-abuse
$ cd gssapi-abuse
$ python3 -m venv venv
$ source ./venv/bin/activate
$ pip3 install -r requirements.txt
```
### Krbrelayx
```
$ git clone https://github.com/dirkjanm/krbrelayx
$ cd krbrelayx
$ python3 -m venv venv
$ source ./venv/bin/activate
$ pip3 install impacket
```
### ntdissector
```
$ git clone https://github.com/synacktiv/ntdissector
$ python3 -m venv venv
$ source ./venv/bin/activate
$ python3 -m pip install ./ntdissector
```
### pyWhisker
```
$ git clone https://github.com/ShutdownRepo/pywhisker
$ cd pywhisker
$ python3 -m venv venv
$ source ./venv/bin/activate
$ pip3 install -r requirements.txt
```
### PetitPotam
```
$ git clone https://github.com/topotam/PetitPotam
$ cd PetitPotam
$ python3 -m venv venv
$ source ./venv/bin/activate
$ pip3 install impacket
```
### pyGPOAbuse
```
$ git clone https://github.com/Hackndo/pyGPOAbuse
$ cd pyGPOAbuse
$ python3 -m venv venv
$ source ./venv/bin/activate
$ pip3 install -r requirements.txt
```
### Responder
```
$ git clone https://github.com/SpiderLabs/Responder
```
### pypykatz
```
$ pip3 install pypykatz
```
### SharpCollection
```
$ git clone https://github.com/Flangvik/SharpCollection
```
### PowerView
```
$ wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Recon/PowerView.ps1
```
### Powermad
```
$ git clone https://github.com/Kevin-Robertson/Powermad
```
### ntlm_theft
```
$ git clone https://github.com/Greenwolf/ntlm_theft
$ cd ntlm_theft
$ python3 -m venv venv
$ source ./venv/bin/activate
$ pip3 install xlsxwriter
```
### Hashgrab
```
$ git clone https://github.com/xct/hashgrab
$ cd hashgrab
$ python3 -m venv venv
$ source ./venv/bin/activate
$ pip3 install -r pylnk3
```
### Sliver
```
$ wget https://github.com/BishopFox/sliver/releases/download/v1.7.3/sliver-server_linux-amd64 -O sliver-server
$ chmod +x sliver-server
$ wget https://github.com/BishopFox/sliver/releases/download/v1.7.3/sliver-client_linux-amd64 -O sliver-client
$ chmod +x sliver-client
```
### RunasCs
```
$ wget https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip
$ unzip RunasCs.zip
```
### GodPotato
```
$ wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe -O gp.exe
```
### PrintSpoofer
```
$ wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
$ wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer32.exe
```
### DeadPotato
```
$ wget https://github.com/lypd0/DeadPotato/releases/download/v1.2/DeadPotato-NET4.exe
```
### ProxyChains-NG
```
$ sudo apt-get install proxychains4
```
### Chisel
```
$ wget https://github.com/jpillora/chisel/releases/download/v1.11.7/chisel_1.11.7_linux_amd64.gz
$ gunzip -d chisel_1.11.7_linux_amd64.gz

$ wget https://github.com/jpillora/chisel/releases/download/v1.11.7/chisel_1.11.7_windows_amd64.zip
$ 7z x chisel_1.11.7_windows_amd64.zip
```
### Ligolo-ng
```
$ wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.3/ligolo-ng_proxy_0.8.3_linux_amd64.tar.gz
$ wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.3/ligolo-ng_agent_0.8.3_linux_amd64.tar.gz
$ wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.3/ligolo-ng_agent_0.8.3_windows_amd64.zip

$ tar xvf ligolo-ng_proxy_0.8.3_linux_amd64.tar.gz
$ tar xvf ligolo-ng_agent_0.8.3_linux_amd64.tar.gz
$ 7z x ligolo-ng_agent_0.8.3_windows_amd64.zip
```
### nc64
```
$ wget https://github.com/int0x33/nc.exe/raw/refs/heads/master/nc64.exe
```
### rcat
```
$ sudo apt update && sudo apt install mingw-w64

$ git clone https://github.com/xct/rcat.git
$ cd rcat

$ rustup target add x86_64-pc-windows-gnu
$ rustup toolchain install stable-x86_64-pc-windows-gnu

$ cargo build --release --target x86_64-pc-windows-gnu ### windows
$ cargo build --release ### linux

# verify
$ ls target/release/rcat
$ ls target/x86_64-pc-windows-gnu/release/rcat.exe
```
### ConPtyShell
```
$ wget https://github.com/antonioCoco/ConPtyShell/releases/download/1.5/ConPtyShell.zip
$ wget https://raw.githubusercontent.com/antonioCoco/ConPtyShell/refs/heads/master/Invoke-ConPtyShell.ps1
```
### Winpspy
Build with Visual Studio
```
$ git clone https://github.com/xct/winpspy
```
### winPEAS
```
$ wget https://github.com/peass-ng/PEASS-ng/releases/download/20260630-cc3f91c1/winPEASx64.exe
```
### PrivescCheck
```
$ wget https://github.com/itm4n/PrivescCheck/releases/download/2026.04.29-1/PrivescCheck.ps1
```
### LaZagne
```
$ wget https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.7/LaZagne.exe
```
## Resources
- Python Tools and Scripts w/ UV CheatSheet by 0xdf: https://0xdf.gitlab.io/cheatsheets/uv
