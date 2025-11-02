# AD-Tools
List of some AD tools I frequently use

# Table of Contents
- [Recommendations](#recommendations)
- [Installation](#installation)
  - [netexec](#netexec)
  - [impacket](#impacket)
  - [BloodHound](#bloodhound)
  - [BloodHound.py Legacy](#bloodhoundpy-legacy)
  - [BloodHound.py CE](#bloodhoundpy-ce)
  - [bofhound](#bofhound)
  - [RustHound](#rusthound)
  - [bloodyAD](#bloodyad)
  - [powerview.py](#powerviewpy)
  - [certipy](#certipy)
  - [PKINITtools](#pkinittools)
  - [targetedKerberoast](#targetedkerberoast)
  - [gssapi-abuse](#gssapi-abuse)
  - [krbrelayx](#krbrelayx)
  - [ntdissector](#ntdissector)
  - [sliver](#sliver)
  - [Responder](#responder)
  - [pypykatz](#pypykatz)
  - [pywhisker](#pywhisker)
  - [PetitPotam](#petitpotam)
  - [pyGPOAbuse](#pygpoabuse)
  - [SharpCollection](#sharpcollection)
  - [PowerView](#powerview)
  - [Powermad](#powermad)
  - [ntlm_theft](#ntlm_theft)
  - [hashgrab](#hashgrab)
  - [RunasCs](#runascs)
  - [GodPotato](#godpotato)
  - [PrintSpoofer](#printspoofer)
  - [DeadPotato](#deadpotato)
  - [proxychains](#proxychains)
  - [chisel](#chisel)
  - [ligolo-ng](#ligolo-ng)
  - [nc64.exe](#nc64exe)
  - [rcat](#rcat)
  - [ConPtyShell](#conptyshell)
  - [winpspy](#winpspy)
  - [winPEAS](#winpeas)
  - [PrivescCheck](#privesccheck)
  - [LaZagne](#lazagne)

## Recommendations
- It is recommended to use `pipx` whenever possible for installing command-line python applications to keep them isolated.
- It is also recommended to use a python virtual environment when installing tools to avoid breaking system-wide packages.
```
python3 -m venv venv
source venv/bin/activate
(venv) ➜
# to exit the virtual env
(venv) deactivate
```
## Installation
### netexec
```
sudo apt install pipx git
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
```
### impacket
```
python3 -m pipx install impacket
```
### BloodHound
```
wget https://github.com/BloodHoundAD/BloodHound/releases/download/v4.3.1/BloodHound-linux-x64.zip
unzip BloodHound-linux-x64.zip
mv BloodHound-linux-x64 BloodHound
./BloodHound --disable-gpu-sandbox
```
Add this alias to the `~/.zshrc` file
```
alias bloodhound="~/tools/BloodHound/BloodHound --disable-gpu-sandbox"
```
### BloodHound.py Legacy
```
pipx install bloodhound
```
### BloodHound.py CE
```
pipx install bloodhound-ce
```
### bofhound
```
pip3 install bofhound
```
### RustHound
```
git clone https://github.com/NH-RED-TEAM/RustHound.git
```
Install rust
```
curl https://sh.rustup.rs -sSf | sh
```
Build
```
cd RustHound
make install
```
### bloodyAD
```
pipx install bloodyAD
```
### powerview.py
```
sudo apt install libkrb5-dev
pipx install "git+https://github.com/aniqfakhrul/powerview.py"
```
### certipy
Using pip
```
python3 -m venv certipy-venv
source certipy-venv/bin/activate
pip install certipy-ad
```
Using pipx
```
pipx install -f "git+https://github.com/ly4k/Certipy.git"
```
### PKINITtools
```
git clone https://github.com/dirkjanm/PKINITtools
```
### targetedKerberoast
```
git clone https://github.com/ShutdownRepo/targetedKerberoast
```
### gssapi-abuse
```
git clone https://github.com/CCob/gssapi-abuse
```
### krbrelayx
```
git clone https://github.com/dirkjanm/krbrelayx
```
### ntdissector
```
git clone https://github.com/synacktiv/ntdissector
python3 -m pip install ./ntdissector
```
### sliver
```
wget https://github.com/BishopFox/sliver/releases/download/v1.5.44/sliver-server_linux -O sliver-server
chmod +x sliver-server
wget https://github.com/BishopFox/sliver/releases/download/v1.5.44/sliver-client_linux -O sliver-client
chmod +x sliver-client
```
### Responder
```
git clone https://github.com/SpiderLabs/Responder.git
```
### pypykatz
```
pip3 install pypykatz
```
### pywhisker
```
git clone https://github.com/ShutdownRepo/pywhisker.git
```
### PetitPotam
```
git clone https://github.com/topotam/PetitPotam.git
```
### pyGPOAbuse
```
git clone https://github.com/Hackndo/pyGPOAbuse.git
```
### SharpCollection
```
git clone https://github.com/Flangvik/SharpCollection
```
### PowerView
```
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Recon/PowerView.ps1
```
### Powermad
```
git clone https://github.com/Kevin-Robertson/Powermad.git
```
### ntlm_theft
```
git clone https://github.com/Greenwolf/ntlm_theft
```
### hashgrab
```
git clone https://github.com/xct/hashgrab
```
### RunasCs
```
wget https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip
unzip RunasCs.zip
```
### GodPotato
```
wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe -O gp.exe
```
### PrintSpoofer
```
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer32.exe
```
### DeadPotato
```
wget https://github.com/lypd0/DeadPotato/releases/download/v1.2/DeadPotato-NET4.exe
```
### proxychains
```
sudo apt-get install proxychains4
```
### chisel
```
wget https://github.com/jpillora/chisel/releases/download/v1.11.3/chisel_1.11.3_linux_amd64.gz
gunzip -d chisel_1.11.3_linux_amd64.gz

wget https://github.com/jpillora/chisel/releases/download/v1.11.3/chisel_1.11.3_windows_amd64.zip
7z x chisel_1.11.3_windows_amd64.zip
```
### ligolo-ng
```
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
wget wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_windows_amd64.zip

tar xvf ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
tar xvf ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
7z x ligolo-ng_agent_0.8.2_windows_amd64.zip
```

### nc64.exe
```
wget https://github.com/int0x33/nc.exe/raw/refs/heads/master/nc64.exe
```
### rcat
```
git clone https://github.com/xct/rcat.git
sudo apt update && sudo apt install mingw-w64
cd rcat
rcat git:(main) rustup target add x86_64-pc-windows-gnu
rcat git:(main) rustup toolchain install stable-x86_64-pc-windows-gnu
rcat git:(main) cargo build --release --target x86_64-pc-windows-gnu ### windows
rcat git:(main) cargo build --release ### linux
rcat git:(main) ls target/release/rcat
target/release/rcat
rcat git:(main) ls target/x86_64-pc-windows-gnu/release/rcat.exe
target/x86_64-pc-windows-gnu/release/rcat.exe
```
### ConPtyShell
```
wget https://github.com/antonioCoco/ConPtyShell/releases/download/1.5/ConPtyShell.zip
wget https://raw.githubusercontent.com/antonioCoco/ConPtyShell/refs/heads/master/Invoke-ConPtyShell.ps1
```
### winpspy
```
git clone https://github.com/xct/winpspy

Build with Visual Studio
```
### winPEAS
```
wget https://github.com/peass-ng/PEASS-ng/releases/download/20240922-a5703fe8/winPEASx64.exe
```
### PrivescCheck
```
wget https://github.com/itm4n/PrivescCheck/releases/download/2025.10.06-1/PrivescCheck.ps1
```
### LaZagne
```
wget https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.7/LaZagne.exe
```
