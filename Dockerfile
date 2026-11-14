FROM ubuntu:22.04

# Prevenir preguntas interactivas durante la instalación de paquetes
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Instalar dependencias requeridas para compilación nativa y validación
RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ \
    make \
    libgmp-dev \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Copiar archivos fuente del proyecto
COPY qoriproof.cpp test_ffi.py /app/

# Compilar la librería compartida optimizada (-O3, -fPIC, enlazada contra GMP/GMPXX)
RUN g++ -O3 -shared -fPIC qoriproof.cpp -lgmpxx -lgmp -o libqoriproof.so

# Ejecutar el script de prueba FFI
CMD ["python3", "test_ffi.py"]
