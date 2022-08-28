/bin/bash
# por wondR & Userware / ES HR
# instalación: +- 3 horas
# Última actualización: 30 de junio de 2022
# OS: Kali Linux / versión:2022.2
# Debes ejecutar este script como ROOT **
# ¡¡¡APAGA EL PROTECTOR DE PANTALLA!!!

ROOT_DIR=/root
RESPONDER_DIR=/usr/share/responder/tools/
PTF_DIR=/opt/package-manager/ptf

apt-get install lolcat

lolcat <<"EOF"

  __
    ----__                               
    --------__
    -------------__
    ------------------__
    ----------------------__ 
    :'######:::'##::::'##::'#######:::'######::'########:'########:::::'###:::::'######::'##:::'##:
    '##... ##:: ##:::: ##:'##.... ##:'##... ##:... ##..:: ##.... ##:::'## ##:::'##... ##: ##::'##::
     ##:::..::: ##:::: ##: ##:::: ##: ##:::..::::: ##:::: ##:::: ##::'##:. ##:: ##:::..:: ##:'##:::
     ##::'####: #########: ##:::: ##:. ######::::: ##:::: ########::'##:::. ##: ##::::::: #####::::
     ##::: ##:: ##.... ##: ##:::: ##::..... ##:::: ##:::: ##.....::: #########: ##::::::: ##. ##:::
     ##::: ##:: ##:::: ##: ##:::: ##:'##::: ##:::: ##:::: ##:::::::: ##.... ##: ##::: ##: ##:. ##::
    . ######::: ##:::: ##:. #######::. ######::::: ##:::: ##:::::::: ##:::: ##:. ######:: ##::. ##:
    :......::::..:::::..:::.......::::......::::::..:::::..:::::::::..:::::..:::......:::..::::..::
              _                                               ___                              
             ((_          \-^-/          (((      < - - - - -()_ \      |||           '*`      
            (o o)         (o o)         (o o)             !!   | |     (o o)         (o o)     
        ooO--(_)--Ooo-ooO--(_)--Ooo-ooO--(_)--Ooo------------------ooO--(_)--Ooo-ooO--(_)--Ooo-                

\\------____-------//-------____-------\\ wondR // Userware \\----\\

EOF

fecha_actual=$(fecha)
echo "A partir de $fecha_actual"

# comprueba si somos ROOT
if [ $EUID -ne 0 ]; then
  echo "Este script debe ser ejecutado como root".
  exit 1
fi

# habilitar el alias de comandos
shopt -s expandir_aliases

# omitir los avisos en apt-upgrade...
export DEBIAN_FRONTEND=noninteractive
alias apt-get='yes "" | apt-get -o Dpkg::Options::="--force-confdef" -y'
apt-get update

# arreglar bashrc
cp /root/.bashrc /root/.bashrc.bak
cp "/home/$(grep -F 1000:1000 /etc/passwd | cut -d: -f1)/.bashrc" /root/.bashrc
. /root/.bashrc


lolcat <<"EOF"

AÑADIENDO 🆂🅾🆄🆁🅲🅴-🅻🅸🆂🆃

EOF

echo "añadiendo lista de fuentes.."
echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" | sudo tee /etc/apt/sources.list
echo "deb-src http://http.kali.org/kali kali-rolling main contrib non-free" | sudo tee -a /etc/apt/sources.list

# actualizar la distro
apt-get dist-upgrade -y
printf '\n---//---\\-----//---\\---\n\n'

printf '\n ▌│"║▌║▌║ Instalación de paquetes ▌│"║▌║▌║\n'
printf '\n -------------------------------------\n\n'
dpkg --add-architecture i386
apt install -y git wget gnupg2 build-essential binutils-dev vim unzip libssl-dev autoconf automake libtool npm graphviz golang ufw bleachbit 
apt install -y konsole xclip freerdp2-x11 powershell tor torsocks wine64 mingw-w64 binutils-mingw-w64-i686 binutils-mingw-w64-x86-64 
apt install -y g++-mingw-w64 g++-mingw-w64-i686 g++-mingw-w64-x86-64 gcc-mingw-w64 gcc-mingw-w64-base gcc-mingw-w64-i686 gcc-mingw-w64-x86-64 
apt install -y mingw-w64 mingw-w64-common mingw-w64-i686-dev mingw-w64-x86-64-dev golang rustc gcc ttf-mscorefonts-installer python3-pip 
apt install -y python3-wheel libcompress-raw-lzma-perl python3-venv fpc gdc ldc ca-certificates lsb-release gem software-properties-common 
apt install -y debian-keyring cargo geany gdebi gufw bleachbit iptables tmux libffi-dev docker.io aptitude libunwind-dev awscli doona 
apt install -y dotdotpwn linux-exploit-suggester oscanner siparmyknife xsser knockpy urlextractor pompem dirsearch python3-xlrd python-xlrd-docs
ufw enable
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Instalando PTF ▌│"║▌║▌║\n'
printf '\n --------------------------------\n\n'
git clone https://github.com/trustedsec/ptf/ /opt/package-manager/ptf
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Instalando Python3 ▌│"║▌║▌║\n'
printf '\n ------------------------------------\n\n'
apt-get -y install python3-venv 
python3 -m pip install pipenv
pip3 install pyReadline habu getips virtualenvwrapper uncompyle6 git-filter-repo python-whois colorama bs4 virtualenv wheel boto3 botocore termcolor requests pycryptodome
printf '\n---//---\\-----//---\\---\n\n'
 

printf '\n ▌│"║▌║▌║ Colección de información ▌│"║▌║▌║\n'
printf '\n ---------------------------------------\n\n'
apt autoremove -y dmitry
apt install -y ike-scan legion maltego netdiscover nmap p0f recon-ng spiderfoot dnsenum dnsmap dnsrecon dnstracer dnswalk fierce urlcrazy firewalk lbd wafw00f arping fping hping3 masscan zmap ncat thc- ipv6 unicornscan theharvester netmask enum4linux polenum nbtscan nbtscan-unixwiz smbmap smtp-user-enum swaks braa onesixtyone snmp ssldump sslh sslscan sslyze fragrouter ftester arp-scan t50 ipv6-toolkit
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Análisis de vulnerabilidad ▌│║▌║▌║\n'
printf '\n ----------------------------------------\n\n'
apt install -y lynis nikto unix-privesc-check linux-exploit-suggester windows-privesc-check yersinia bed sfuzz siparmyknife spike iaxflood inviteflood siege thc-ssl- dos rtpbreak rtpflood rtpinsertsound sctpscan sipp sipsak sipvicious cisco-auditing-tool cisco-global-exploiter cisco-ocs cisco-torch copy-router-config perl-cisco-copyconfig
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Análisis de aplicaciones web ▌│║▌║▌║\n'
printf '\n ------------------------------------------\n\n'
apt install -y burpsuite commix skipfish sqlmap wpscan zaproxy cutycapt dirb dirbuster wfuzz ffuf cadaver davtest wapiti whatweb xsser dotdotpwn sublist3r gobuster apache-users hurl jboss-autopwn jsql jsql-injection
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Evaluación de la base de datos ▌│"║▌║▌║\n'
printf '\n -------------------------------------\n\n'
apt install -y oscanner sidguesser sqlitebrowser sqsh
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Ataques de contraseña ▌│"║▌║▌║\n'
printf '\n ----------------------------------\n\n'
apt install -y cewl crunch hashcat john medusa ophcrack wordlists seclists chntpw crackle fcrackzip hashid hash-identifier samdump2 hydra patator thc-pptp-bruter mimikatz passing-the-hash rsmangler pdfcrack
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Ataques inalámbricos ▌│"║▌║▌║\n'
printf '\n ----------------------------------\n\n'
apt install -y aircrack-ng chirp cowpatty fern-wifi-cracker kismet mfoc mfterm pixiewps reaver wifite bully wifi-honey bluelog btscanner redfang spooftooph ubertooth ubertooth-firmware gnuradio gqrx-sdr rfcat rfdump rtlsdr-scanner
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Ingeniería inversa ▌│"║▌║▌║\n'
printf '\n -------------------------------------\n\n'
apt install -y apktool bytecode-viewer clang dex2jar edb-debugger javasnoop ollydbg radare2 radare2-cutter
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Herramientas de Explotación ▌│"║▌║▌║\n'
printf '\n ------------------------------------\n\n'
apt install -y metasploit-framework powershell-empire msfpc exploitdb shellnoob termineter beef-xss merlin-agent merlin-server koadic kerberoast routersploit payloadsallthethings upx-ucl
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Sniffing & Spoofing ▌│"║▌║▌║\n'
printf '\n -------------------------------------\n\n'
apt install -y bettercap bettercap-caplets bettercap-ui ettercap-common ettercap-graphical macchanger mitmproxy netsniff-ng responder wireshark dnschef hexinject tcpflow isr-evilgrade fiked rebind sslsplit tcpreplay
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Multirelay ▌│"║▌║▌║\n'
printf '\n ----------------------------\n\n'
cd $RESPONDER_DIR
apt install -y gcc-mingw-w64-x86-64 && \N-
sudo x86_64-w64-mingw32-gcc ./MultiRelay/bin/Runas.c -o ./MultiRelay/bin/Runas.exe -municode -lwtsapi32 -luserenv && \
sudo x86_64-w64-mingw32-gcc ./MultiRelay/bin/Syssvc.c -o ./MultiRelay/bin/Syssvc.exe -municode
cd $ROOT_DIR
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Post Explotación ▌│"║▌║▌║\n'
printf '\n -----------------------------------\n\n'
apt install -y exe2hexbat powersploit nishang proxychains4 privoxy shellter veil weevely unicorn-magic dbd sbd dns2tcp iodine miredo proxytunnel ptunnel- ng pwnat stunnel4 udptunnel 6tunnel httptunnel chisel laudanum powercat ncat-w32 cryptcat dnscat2 winexe windows-binaries secure-socket-funneling-windows-binaries crackmapexec rlwrap putty-tools pwncat sshuttle
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Instalando herramientas ▌│"║▌║▌║\n'
printf '\n ----------------------------------\n\n'
mkdir /opt/bruteforce/ && \N
git clone https://github.com/fuzzdb-project/fuzzdb.git /opt/bruteforce/fuzzdb/ && \
git clone https://github.com/danielmiessler/SecLists.git /opt/bruteforce/SecLists/ && \
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /opt/bruteforce/PayloadsAllTheThings/ && \
git clone https://github.com/1N3/IntruderPayloads /opt/bruteforce/IntruderPayloads/ && \
git clone https://github.com/vanhauser-thc/thc-hydra.git /opt/bruteforce/thc-hydra/
mkdir /opt/dorkfuzz/ && \
git clone https://github.com/s0md3v/Photon.git /opt/dorkfuzz/Photon/ && \
git clone https://github.com/FrancescoDiSalesGithub/dorker /opt/dorkfuzz/dorker/ && \
git clone https://github.com/GerbenJavado/LinkFinder.git /opt/dorkfuzz/LinkFinder/
mkdir /opt/recon/ && \
git clone https://github.com/AlisamTechnology/ATSCAN.git /opt/recon/ATSCAN/ && \
git clone https://github.com/tahmed11/DeepScan.git /opt/recon/DeepScan/ && \
git clone https://github.com/machine1337/fast-scan.git /opt/recon/fast-scan/ && \
git clone https://github.com/kakawome/Lethe.git /opt/recon/Lethe/ && \
git clone https://github.com/NeverWonderLand/tellme.git /opt/recon/ && \
git clone https://github.com/Ha3MrX/Hacking.git /opt/recon/Hacking/
mkdir /opt/osint/ && \
git clone https://github.com/BullsEye0/ghost_eye.git /opt/osint/ghost_eye/ && \
git clone https://github.com/trustedsec/social-engineer-toolkit.git /opt/osint/social-engineer-toolkit/ && \
git clone https://github.com/Ignitetch/AdvPhishing.git /opt/osint/AdvPhishing/ && \
git clone https://github.com/sherlock-project/sherlock.git /opt/osint/sherlock/ && \
git clone https://github.com/BLINKING-IDIOT/Aliens_eye /opt/osint/Aliens_eye/
mkdir /opt/ddos/ && \
git clone https://github.com/NeverWonderLand/Impulse.git /opt/ddos/Impulse/ && \
git clone https://github.com/7zx/overload.git /opt/ddos/overload/ && \
git clone https://github.com/H1R0GH057/Anonymous.git /opt/ddos/Anonymous/ && \
git clone https://github.com/firstapostle/Blood /opt/ddos/Blood/ && \
git clone https://github.com/UBISOFT-1/AnonymousPAK-DDoS /opt/ddos/AnonymousPAK-DDoS/
mkdir /opt/shells/ && \
git clone https://github.com/machine1337/mafiahacks.git /opt/shells/mafiahacks/ && \
git clone https://github.com/BlackArch/webshells.git /opt/shells/webshells/ && \
git clone https://github.com/t0thkr1s/revshellgen.git /opt/shells/revshellgen/
git clone https://github.com/GreatSCT/GreatSCT.git /opt/av-bypass/GreatSct/ && \
git clone https://github.com/mdsecactivebreach/SharpShooter.git /opt/av-bypass/SharpShooter/
git clone https://github.com/84KaliPleXon3/GitHackTools-TorghostNG /opt/anonymity/TorghostNG/
git clone https://github.com/Kevin-Robertson/Inveigh /opt/exploitation/Inveigh/ && \
git clone https://github.com/bettercap/bettercap.git /opt/exploitation/bettercap/ && \
git clone https://github.com/ropnop/kerbrute /opt/exploitation/kerbrute/
git clone https://github.com/carlospolop/PEASS-ng /opt/intelligence-gathering/PEASS-ng/ && \
git clone https://github.com/jondonas/linux-exploit-suggester-2.git /opt/intelligence-gathering/linux-exploit-suggester-2/ && \
git clone https://github.com/rebootuser/LinEnum.git /opt/intelligence-gathering/LinEnum/ && \
git clone https://github.com/diego-treitos/linux-smart-enumeration.git /opt/intelligence-gathering/linux-smart-enumeration && \
git clone https://github.com/linted/linuxprivchecker.git /opt/intelligence-gathering/linuxprivchecker && \
git clone https://github.com/mostaphabahadou/postenum.git /opt/intelligence-gathering/postenum/ && \
git clone https://github.com/bitsadmin/wesng /opt/intelligence-gathering/wesng/ && \
git clone https://github.com/GhostPack/SharpUp /opt/intelligence-gathering/SharpUp/ && \
git clone https://github.com/GhostPack/Seatbelt /opt/intelligence-gathering/Seatbelt/
git clone --recurse-submodules https://github.com/cobbr/Covenant /opt/post-exploitation/Covenant && \
git clone https://github.com/n1nj4sec/pupy/ /opt/post-explotación/pupy/ && \
git clone https://github.com/SafeBreach-Labs/SirepRAT /opt/post-exploitation/SirepRAT/
git clone https://github.com/nil0x42/phpsploit /opt/webshells/phpsploit/
git clone https://github.com/gchq/CyberChef.git /opt/reversing/CyberChef/
git clone https://github.com/sundowndev/covermyass.git /opt/anti-forensics/covermyass/
git clone https://github.com/leostat/rtfm /opt/miscellaneous/rtfm/
git clone https://github.com/r00t0v3rr1d3/armitage.git /opt/armitage
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Instalando pwncat ▌│"║▌║▌║\n'
printf '\n -----------------------------------\n\n'
python3 -m venv /opt/pwncat
/opt/pwncat/bin/pip install 'git+https://github.com/calebstewart/pwncat'
ln -s /opt/pwncat/bin/pwncat /usr/local/bin
git clone https://github.com/calebstewart/pwncat.git /opt/post-explotación/pwncat/ 
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Forense ▌│"║▌║▌║\n'
printf '\n ---------------------------\n\n'
apt install -y autopsy binwalk bulk-extractor chkrootkit foremost hashdeep rkhunter yara extundelete magicrescue recoverjpeg safecopy scalpel scrounge-ntfs guymager pdfid pdf-parser python3-pdfminer
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Anti-Forensics ▌│"║▌║▌║\n'
printf '\n --------------------------------\n\n'
apt install -y mat2 wipe
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Herramientas para la elaboración de informes ▌│"║▌║▌║\n'
printf '\n ---------------------------------\n\n'
apt install -y dradis eyewitness faraday pipal metagoofil
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Herramientas de ingeniería social ▌│║▌║▌║\n'
printf '\n ------------------------------------------\n\n'
apt install -y set king-phisher wifiphisher
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ PTF ▌│"║▌║▌║\n'
printf '\n ---------------------\n\n'
cd $PTF_DIR
./ptf <<EOF
use modules/pivoting/3proxy
ejecutar
use modules/pivoting/meterssh
ejecutar
use modules/pivoting/pivoter
ejecutar
use modules/pivoting/rpivot
ejecutar
use modules/av-bypass/pyobfuscate
ejecutar
use modules/exploitation/fido
ejecutar
use modules/exploitation/fuxploider
ejecutar
use modules/exploitation/impacket
ejecutar
use modules/exploitation/inception
ejecutar
use modules/exploitation/kerberoast
ejecutar
use modules/exploitation/mitm6
ejecutar
use modules/exploitation/pwntools
ejecutar
use modules/webshells/b374k
ejecutar
use modules/webshells/blackarch
ejecutar
use modules/webshells/wso
ejecutar
use modules/intelligence-gathering/amass
ejecutar
use modules/intelligence-gathering/autorecon
ejecutar
use modules/intelligence-gathering/awsbucket
ejecutar
use modules/intelligence-gathering/massdns
ejecutar
use modules/intelligence-gathering/windows-exploit-suggester
ejecutar
use modules/password-recovery/statistically-likely-usernames
ejecutar
use modules/post-exploitation/donut
ejecutar
use modules/post-exploitation/evilwinrm
ejecutar
use modules/vulnerability-analysis/golismero
ejecutar
use modules/powershell/obfuscation
ejecutar
use modules/powershell/powersccm
ejecutar
EOF
cd $ROOT_DIR
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ binarios de Putty ▌│"║▌║▌║\n'
printf '\n --------------------------------\n\n'
mkdir /opt/Putty/ && \N
wget https://the.earth.li/~sgtatham/putty/latest/w64/putty.zip -O /opt/Putty/putty64.zip && \
wget https://the.earth.li/~sgtatham/putty/latest/w32/putty.zip -O /opt/Putty/putty32.zip && \
wget https://the.earth.li/~sgtatham/putty/latest/wa64/putty.zip -O /opt/Putty/puttywa64.zip && \
wget https://the.earth.li/~sgtatham/putty/latest/wa32/putty.zip -O /opt/Putty/puttywa32.zip && \
unzip /opt/Putty/putty32.zip -d /opt/Putty/x64/ && \
unzip /opt/Putty/putty64.zip -d /opt/Putty/x86/ && \
unzip /opt/Putty/puttywa32.zip -d /opt/Putty/ARM-32 && \
descomprimir /opt/Putty/puttywa64.zip -d /opt/Putty/ARM-64
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│"║▌║▌║ Windows Sysinternals Suite ▌│"║▌║▌║\n'
printf '\n --------------------------------------------\n\n'
mkdir /opt/SysinternalsSuite/ && \N
wget https://download.sysinternals.com/files/SysinternalsSuite.zip -O /opt/SysinternalsSuite/SysinternalsSuite.zip && \N
wget https://download.sysinternals.com/files/SysinternalsSuite-Nano.zip -O /opt/SysinternalsSuite/SysinternalsSuite-Nano.zip && \N
wget https://download.sysinternals.com/files/SysinternalsSuite-ARM64.zip -O /opt/SysinternalsSuite/SysinternalsSuite-ARM64.zip && \
wget https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip -O /usr/share/windows-resources/binaries/netcat-win32-1.12.zip && \
unzip /opt/SysinternalsSuite/SysinternalsSuite.zip -d /opt/SysinternalsSuite/x64_x86 && \
descomprimir /opt/SysinternalsSuite/SysinternalsSuite-Nano.zip -d /opt/SysinternalsSuite/NANO/ && \
unzip /opt/SysinternalsSuite/SysinternalsSuite-ARM64.zip -d /opt/SysinternalsSuite/ARM-64/ && \
unzip /usr/share/windows-resources/binaries/netcat-win32-1.12.zip -d /usr/share/windows-resources/binaries/nc/
printf '\n---//---\\-----//---\\---\n\n'


printf '\n ▌│║▌║▌║ Instalar Rustscan ▌│║▌║▌║\n'
printf '\n ----------------------------------\n\n'
cargo install rustscan
printf '\n---//---\\-----//---\\---\n\n'


echo "Actualizando.."
apt-get update -y


printf '\n ▌│"║▌║▌║ Instalando gem.. 
printf '\n ----------------------------------\n\n'
gem install bundler && bundle config set --locale without test
gem install rubygems-update
apt full-upgrade
gem install wpscan
printf '\n---//---\\-----//---\\---\n\n'
 

printf '\n ▌│"║▌║▌║ Docker ▌│"║▌║▌║\n'
printf '\n ------------------------\n\n'
# habilitar e iniciar docker
systemctl stop docker &>/dev/null
echo '{"bip":"172.16.199.1/24"}' >/etc/docker/daemon.json
systemctl enable docker --now
printf '\n---//---\\-----//---\\---\n\n'


printf '\n Instalación de Metasploit-framework \n'
printf '\n------------------------------------------------------------------\n\n'

curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb >msfinstall &&
    chmod 755 msfinstall &&
    ./msfinstall

# para evitar el problema con apt-key 
echo 'deb http://apt.metasploit.com/ lucid main' > /etc/apt/sources.list.d/metasploit-framework.list
wget -nc http://apt.metasploit.com/metasploit-framework.gpg.key
cat metasploit-framework.gpg.key | gpg --dearmor > metasploit-framework.gpg
install -o root -g root -m 644 metasploit-framework.gpg /etc/apt/trusted.gpg.d/
apt-get update

# Inicializando la base de datos de Metasploit
systemctl start postgresql
systemctl enable postgresql
msfdb init

printf '\n---//---\\-----//---\\---\n\n'


# iniciando el servicio
service postgresql start
service tor start
service mysql start
/etc/init.d/apache2 start
echo "
Iniciando servicios.. 
======================
-PostgreSQL
-Tor
-Apache
-Mysql
...
"

printf '\n---//---\\-----//---\\---\n\n'

printf '\n▌│║▌║▌║ Configuración de GO ▌│║▌║▌║\n'
printf '\n-------------------------------------\n\n'
cd $ROOT_DIR/
wget -q -O - https://raw.githubusercontent.com/canha/golang-tools-install-script/master/goinstall.sh | bash

printf '\n---//---\\-----//---\\---\n\n'

# -------------------------------------------------------
# Settings
# -------------------------------------------------------

echo "Actualizando..."
apt-get update
apt-get upgrade

printf '\n---//---\\-----//---\\---\n\n'
 

# configuración por defecto de tmux
cat <<EOF >$HOME/.tmux.conf
    set -g mouse on
    set -g history-limit 50000
    set -g prefix2 C-a
    bind C-a send-prefix 
    unbind C-b
    set-window-option -g mode-keys vi

    run-shell /opt/tmux-logging/logging.tmux

    # Lista de plugins
    set -g @plugin 'tmux-plugins/tmux-logging'

    # Inicializar el gestor de plugins TMUX (mantener esta línea en la parte inferior de tmux.conf)
    ejecutar '~/.tmux/plugins/tpm/tpm'
EOF

# =======================================================

printf '\n[+] Habilitando sesión bash\n\n'

grep -q 'UNDER_SCRIPT' ~/.bashrc || echo "if [[ -z "$UNDER_SCRIPT" && -z "$TMUX" && ! -z "$PS1" ]]; then
    logdir=$HOME/Logs 
    if [ ! -d $logdir ]; then
            mkdir $logdir
    fi
    #gzip -q $dir/*.log &>/dev/null
    logfile=$logdir/$(fecha +%F_%H_%M_%S).$$.log
    export UNDER_SCRIPT=$fichero de registro
    script -f -q $fichero de registro
    exit
fi" >>~/.bashrc

printf '\n---//---\\-----//---\\---\n\n' 

echo "Finalizando..."

echo "Limpiando..."
apt-get autoremove -y
apt-get autoclean -y
updatedb


#--------------------------------------------------

# VARIABLES DE ENTORNO
PROMPT_CHAR=$(if [ "$(whoami)" == "root" ]; then echo "#"; else echo "$"; fi)
HOST_COLOR=$(if [ "$(whoami)" == "root" ]; then echo "6"; else echo "1"; fi)
export PS1="\[\e[0;3${HOST_COLOR}m\]\H\[\e[0;37m\]|\[\e[0;32m\]\A\[\e[0;37m\]|\[\e[0;33m\]\w\[\e[0;3${HOST_COLOR}m\] ${PROMPT_CHAR} \N-[1;0m\N-]"
export PATH="$PATH:$HOME/.cargo/bin"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export MSF_DATABASE_CONFIG=~/.msf4/database.yml

# =======================================================

# OTROS AJUSTES Y HACKS
export HISTCONTROL=ignoredups:erasedups # no hay entradas duplicadas
export HISTSIZE=100000 # un gran historial
export HISTFILESIZE=100000 # historial grande
shopt -s histappend # añadir al historial, no sobrescribirlo
# Guarda y recarga el historial después de que termine cada Comando
export PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"

# =======================================================

lolcat <<"EOF"



        GGGGGGGGGGGGGHHHHHHHHH     HHHHHHHHH     OOOOOOOOO        SSSSSSSSSSSSSSS TTTTTTTTTTTTTTTTTTTTTTT    
     GGG::::::::::::GH:::::::H     H:::::::H   OO:::::::::OO    SS:::::::::::::::ST:::::::::::::::::::::T    
   GG:::::::::::::::GH:::::::H     H:::::::H OO:::::::::::::OO S:::::SSSSSS::::::ST:::::::::::::::::::::T    
  G:::::GGGGGGGG::::GHH::::::H     H::::::HHO:::::::OOO:::::::OS:::::S     SSSSSSST:::::TT:::::::TT:::::T    
 G:::::G       GGGGGG  H:::::H     H:::::H  O::::::O   O::::::OS:::::S            TTTTTT  T:::::T  TTTTTT    
G:::::G                H:::::H     H:::::H  O:::::O     O:::::OS:::::S                    T:::::T            
G:::::G                H::::::HHHHH::::::H  O:::::O     O:::::O S::::SSSS                 T:::::T            
G:::::G    GGGGGGGGGG  H:::::::::::::::::H  O:::::O     O:::::O  SS::::::SSSSS            T:::::T            
G:::::G    G::::::::G  H:::::::::::::::::H  O:::::O     O:::::O    SSS::::::::SS          T:::::T            
G:::::G    GGGGG::::G  H::::::HHHHH::::::H  O:::::O     O:::::O       SSSSSS::::S         T:::::T            
G:::::G        G::::G  H:::::H     H:::::H  O:::::O     O:::::O            S:::::S        T:::::T            
 G:::::G       G::::G  H:::::H     H:::::H  O::::::O   O::::::O            S:::::S        T:::::T            
  G:::::GGGGGGGG::::GHH::::::H     H::::::HHO:::::::OOO:::::::OSSSSSSS     S:::::S      TT:::::::TT          
   GG:::::::::::::::GH:::::::H     H:::::::H OO:::::::::::::OO S::::::SSSSSS:::::S      T:::::::::T          
     GGG::::::GGG:::GH:::::::H     H:::::::H   OO:::::::::OO   S:::::::::::::::SS       T:::::::::T          
        GGGGGG   GGGGHHHHHHHHH     HHHHHHHHH     OOOOOOOOO      SSSSSSSSSSSSSSS         TTTTTTTTTTT          
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         
     SSSSSSSSSSSSSSS EEEEEEEEEEEEEEEEEEEEEE       CCCCCCCCCCCCC      
   SS:::::::::::::::SE::::::::::::::::::::E    CCC::::::::::::C      
  S:::::SSSSSS::::::SE::::::::::::::::::::E  CC:::::::::::::::C      
  S:::::S     SSSSSSSEE::::::EEEEEEEEE::::E C:::::CCCCCCCC::::C      
  S:::::S              E:::::E       EEEEEEC:::::C       CCCCCC      
  S:::::S              E:::::E            C:::::C                    
   S::::SSSS           E::::::EEEEEEEEEE  C:::::C                    
    SS::::::SSSSS      E:::::::::::::::E  C:::::C                    
      SSS::::::::SS    E:::::::::::::::E  C:::::C                    
         SSSSSS::::S   E::::::EEEEEEEEEE  C:::::C                    
              S:::::S  E:::::E            C:::::C                    
              S:::::S  E:::::E       EEEEEEC:::::C       CCCCCC      
  SSSSSSS     S:::::SEE::::::EEEEEEEE:::::E C:::::CCCCCCCC::::C      
  S::::::SSSSSS:::::SE::::::::::::::::::::E  CC:::::::::::::::C      
  S:::::::::::::::SS E::::::::::::::::::::E    CCC::::::::::::C      
   SSSSSSSSSSSSSSS   EEEEEEEEEEEEEEEEEEEEEE       CCCCCCCCCCCCC                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
                                                                                                                                                                                                                                                                                                                                             
 MMMMMMMM               MMMMMMMM               AAA               FFFFFFFFFFFFFFFFFFFFFFIIIIIIIIII               AAA               
 M:::::::M             M:::::::M              A:::A              F::::::::::::::::::::FI::::::::I              A:::A              
 M::::::::M           M::::::::M             A:::::A             F::::::::::::::::::::FI::::::::I             A:::::A             
 M:::::::::M         M:::::::::M            A:::::::A            FF::::::FFFFFFFFF::::FII::::::II            A:::::::A            
 M::::::::::M       M::::::::::M           A:::::::::A             F:::::F       FFFFFF  I::::I             A:::::::::A           
 M:::::::::::M     M:::::::::::M          A:::::A:::::A            F:::::F               I::::I            A:::::A:::::A          
 M:::::::M::::M   M::::M:::::::M         A:::::A A:::::A           F::::::FFFFFFFFFF     I::::I           A:::::A A:::::A         
 M::::::M M::::M M::::M M::::::M        A:::::A   A:::::A          F:::::::::::::::F     I::::I          A:::::A   A:::::A        
 M::::::M  M::::M::::M  M::::::M       A:::::A     A:::::A         F:::::::::::::::F     I::::I         A:::::A     A:::::A       
 M::::::M   M:::::::M   M::::::M      A:::::AAAAAAAAA:::::A        F::::::FFFFFFFFFF     I::::I        A:::::AAAAAAAAA:::::A      
 M::::::M    M:::::M    M::::::M     A:::::::::::::::::::::A       F:::::F               I::::I       A:::::::::::::::::::::A     
 M::::::M     MMMMM     M::::::M    A:::::AAAAAAAAAAAAA:::::A      F:::::F               I::::I      A:::::AAAAAAAAAAAAA:::::A    
 M::::::M               M::::::M   A:::::A             A:::::A   FF:::::::FF           II::::::II   A:::::A             A:::::A   
 M::::::M               M::::::M  A:::::A               A:::::A  F::::::::FF           I::::::::I  A:::::A               A:::::A  
 M::::::M               M::::::M A:::::A                 A:::::A F::::::::FF           I::::::::I A:::::A                 A:::::A 
 MMMMMMMM               MMMMMMMMAAAAAAA                   AAAAAAAFFFFFFFFFFF           IIIIIIIIIIAAAAAAA                   AAAAAAA                                                                                                                                                                                                                                                                                                                                   




Ahora necesitas completar manualmente algunos pasos...

# Para no tener que recordar ejecutar msfupdate todo el tiempo, 
# metasploit se actualizará a la 1 de la mañana todos los días y puedes concentrarte en usar la herramienta. 
# Manteniéndolo simple como siempre, ejecute
crontab -e
# Usando tu editor preferido, añade la siguiente línea, sustituye $nombre por tu nombre de usuario:
`0 1 * * * /home/$name/apps/metasploit-framework/msfupdate > /dev/null 2>&amp;1`.


# Instalación de pwncat:
cd /opt/post-exploitation/pwncat/
python3 -m venv pwncat-env
source pwncat-env/bin/activate
pip install pwncat-cs


# Armitage
# Configure la ubicación de la base de datos para Armitage (añada esto en el archivo .bashrc)
sudo msfdb init
sudo nano /etc/postgresql/14/main/pg_hba.conf
# en la línea 97 (conexiones locales IPV4) : cambiar "scram-sha-256" a "trust"
# Luego:
sudo systemctl enable postgresql
sudo systemctl start postgresql


# Configurar iptables
# estos son los mínimos necesarios;
iptables -L -v
iptables -L
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport ssh -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables-save 

EOF

sed -i -r "s:~/:$ROOT_DIR/:" $ROOT_DIR/.bashrc
