#!/bin/bash

# Nombre del script Python
SCRIPT_NAME="portScan.py"
TARGET_NAME="/usr/bin/portScan"

# Función para comprobar si se ejecuta como root
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Este script debe ejecutarse como root"
    exit 1
  fi
}

# Función para instalar los requisitos
install_requirements() {
  echo "Instalando requisitos..."

  # Actualizar la lista de paquetes e instalar pip y otras dependencias
  apt update
  apt install -y python3 python3-pip nmap

  # Instalar las librerías de Python necesarias
  pip3 install termcolor scapy
}

# Función para copiar el script a /usr/bin/
copy_script() {
  echo "Copiando el script a /usr/bin/..."
  cp "$SCRIPT_NAME" "$TARGET_NAME"
  chmod +x "$TARGET_NAME"
}

# Ejecutar funciones
check_root
install_requirements
copy_script

echo "Instalación completada con éxito."
