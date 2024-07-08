# portScan

![portScan Logo](./logo.png)

## Descripción

`portScan` es una herramienta de escaneo de puertos escrita en `Python`, diseñada para la auditoría de redes y el hacking ético. Permite escanear puertos abiertos, cerrados y filtrados en una `IP` o un rango de `IPs`, proporcionando información detallada sobre los servicios que se ejecutan en los puertos abiertos.

## Características

- Escaneo de puertos en una `IP` específica.
- Escaneo de puertos en un rango de `IPs` especificado en notación `CIDR`.
- Muestra solo puertos abiertos con detalles breves.
- Muestra todos los puertos con detalles completos utilizando `nmap`.
- Exporta los resultados del escaneo a un archivo `.txt`.
- Interrupción del escaneo con Ctrl+C mostrando un mensaje de salida.

## Requisitos

- Python 3.x
- `termcolor`
- `scapy`
- `nmap`

## Instalación

1. **Clonar el repositorio**:

    ```bash
    git clone https://github.com/D1se0/portScan.git
    cd portScan
    ```

3. **Ejecutar el script de instalación**:

    ```bash
    ./requirements.sh
    ```

## Uso

La herramienta `portScan` ofrece varias opciones y parámetros para el escaneo de puertos. A continuación se detallan los parámetros y ejemplos de uso.

### Parámetros

- `-i`, `--ip`: Dirección IP única a escanear.
- `-s`, `--subnet`: Notación CIDR para escanear un rango de IPs (por ejemplo, `10.10.11.0/24`).
- `--only-open`: Muestra solo los puertos abiertos con detalles breves.

- `--only-filtered`: Muestra solo los puertos filtrados.
- `--all`: Muestra todos los puertos abiertos con información detallada utilizando `nmap`.
- `--export <archivo>`: Exporta los resultados del escaneo a un archivo `.txt`.

### Ejemplos de uso

1. **Escaneo de puertos en una IP específica**:
    ```bash
    python3 portScan.py -i <IP> --only-open
    ```

2. **Escaneo de un rango de IPs**:
    ```bash
    python3 portScan.py -s <IP>/24 --only-open
    ```
### Example:

```bash
    python3 portScan.py -s 10.10.11.0/24 --only-open
```

3. **Mostrar todos los puertos con detalles completos**:
    ```bash
    python3 portScan.py -i <IP> --all
    ```

4. **Exportar los resultados a un archivo**:
    ```bash
    python3 portScan.py -i <IP> --all --export <FILE>.txt
    ```

## Ejemplo de Salida

### Escaneo con `--only-open`

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

### Escaneo con `--all`

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

## Contribuciones

Las contribuciones son bienvenidas. Por favor, abre un issue o envía un `pull request` para mejorar esta herramienta.

## Licencia

`portScan` está licenciado bajo la MIT License.

----

¡Gracias por usar `portScan`!
