# portScan

<p align="center">
  <img src="https://github.com/D1se0/portScan/assets/164921056/9c78824a-af22-4377-ad6f-774c122f5410" alt="Directorybrute" width="400">
</p>

## Description

`portScan` is a port scanning tool written in `Python`, designed for network auditing and ethical hacking. It allows you to scan open, closed and filtered ports on an `IP` or a range of `IPs`, providing detailed information about the services running on the open ports.

## Characteristics

- Port scanning on a specific `IP`.
- Port scanning in a range of `IPs` specified in `CIDR` notation.
- Shows only open ports with brief details.
- Show all ports with full details using `nmap`.
- Export scan results to a `.txt` file.
- Interrupt the scan with Ctrl+C showing an output message.

## Requirements

- Python 3.x
- `termcolor`
- `scapy`
- `nmap`

## Install

1. **Clone the repository**:

    ```bash
    git clone https://github.com/D1se0/portScan.git
    cd port scan
    ```

3. **Run the installation script**:

    ```bash
    ./requirements.sh
    ```

## Use

The `portScan` tool offers several options and parameters for port scanning. The parameters and usage examples are detailed below.

### Parameters

- `-i`, `--ip`: Unique IP address to scan.
- `-s`, `--subnet`: CIDR notation to scan a range of IPs (e.g. `10.10.11.0/24`).
- `--only-open`: Show only open ports with brief details.

- `--only-filtered`: Show only filtered ports.
- `--all`: Show all open ports with detailed information using `nmap`.
- `--export <file>`: Export the scan results to a `.txt` file.

### Examples of use

1. **Port scanning on a specific IP**:

    ```bash
    python3 portScan.py -i <IP> --only-open
    ```

3. **Scanning a range of IPs**:

    ```bash
    python3 portScan.py -s <IP>/24 --only-open
    ```

    ### Example:

    ```bash
    python3 portScan.py -s 10.10.11.0/24 --only-open
    ```

3. **Show all ports with full details**:

    ```bash
    python3 portScan.py -i <IP> --all
    ```

5. **Export results to a file**:

    ```bash
    python3 portScan.py -i <IP> --all --export <FILE>.txt
    ```

## Output Example

### Scanning with `--only-open`

```plaintext
    ****************************************
    *                                      *
    *            portScan Tool             *
    *            portScan v1.0             *
    *           by Diseo (@d1se0)          *
    *                                      *
    ****************************************

Scanning 192.168.5.132...
Detailed information for open ports:
Port 21 is open
 - Service: ftp
 - Protocol: TCP
Port 22 is open
 - Service: ssh
 - Protocol: TCP
Port 80 is open
 - Service: http
 - Protocol: TCP

Scan completed in: 0:00:35.303330
```

### Scan with `--all`

```bash
    ****************************************
    *                                      *
    *            portScan Tool             *
    *            portScan v1.0             *
    *           by Diseo (@d1se0)          *
    *                                      *
    ****************************************

Scanning 192.168.5.132...

Nmap scan report for 192.168.5.132
Host is up (0.00029s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 192.168.5.199
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u4 (protocol 2.0)
| ssh-hostkey:
|   2048 f6:b2:97:f0:f1:27:17:64:94:31:03:1b:67:5d:14:da (RSA)
|   256 66:76:43:83:5c:e7:19:39:81:35:90:be:b8:44:43:5e (ECDSA)
|_  256 69:91:f4:79:f9:3d:2b:d7:58:15:46:3b:b0:3a:d2:97 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 00:0C:29:8F:E1:EA (VMware)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 37.03 seconds
```

## Contributions

Contributions are welcome. Please open an issue or submit a pull request to improve this tool.

## License

`portScan` is licensed under the MIT License.

----

Thank you for using `portScan`!
