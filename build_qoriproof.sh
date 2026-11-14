#!/usr/bin/env bash
# ==============================================================================
# QoriProof - Build & Test Orchestration Script
# ==============================================================================
# Architecture: Native C++ Cryptographic Core with GMP & C ABI FFI Bridge
# Target Consumer: Mobile Flutter Application (Dart FFI)
# Verification Harness: Python (ctypes) within isolated Ubuntu Docker container
# ==============================================================================
set -euo pipefail

echo "======================================================================"
echo " [QoriProof] Iniciando generación de artefactos y entorno de pruebas"
echo "======================================================================"

# ------------------------------------------------------------------------------
# 1. GENERACIÓN DEL ARCHIVO FUENTE C++ (qoriproof.cpp)
# ------------------------------------------------------------------------------
echo ">> [1/3] Generando qoriproof.cpp..."

cat << 'EOF' > qoriproof.cpp
#include <gmpxx.h>
#include <string>
#include <cstring>
#include <iostream>
#include <sstream>

/**
 * ============================================================================
 * GESTIÓN DE MEMORIA ZERO-ALLOCATION EN PUENTES FFI (DART <-> C++)
 * ============================================================================
 * 
 * 1. El Problema del Heap Cruzado y Memory Leaks:
 *    En entornos móviles como Flutter (Dart VM), solicitar a una biblioteca C/C++
 *    que asigne memoria dinámica (malloc / new) y devuelva un puntero crea dos
 *    riesgos críticos:
 *      a) Fugas de Memoria: Dart Garbage Collector no puede rastrear punteros
 *         nativos huérfanos sin llamadas explícitas a free().
 *      b) Corrupción de Memoria: Mezclar runtime allocators (e.g., glibc en Linux,
 *         Bionic en Android, libc++ en iOS, Dart GC) genera fallos catastróficos
 *         si el llamador intenta liberar memoria asignada por otro gestor.
 * 
 * 2. El Patrón "Caller-Allocated Buffer" (Zero-Allocation Bridge):
 *    - La aplicación cliente (Flutter/Dart o Python ctypes) preasigna un buffer de 
 *      memoria contigua de tamaño fijo en su propio espacio gestionado 
 *      (e.g., `calloc<Uint8>(max_len)` en Dart FFI o `create_string_buffer` en Python).
 *    - El puntero y su capacidad límite (`max_len`) se transfieren a C++ como argumentos.
 *    - C++ ejecuta las operaciones criptográficas sobre la pila o memoria interna GMP
 *      y copia el resultado directamente al buffer preasignado utilizando funciones
 *      con protección de desbordamiento (bounded copy con terminación nula garantizada).
 *    - CERO asignaciones dinámicas escapan del ámbito de la función nativa.
 *    - Al finalizar la ejecución de la función, la memoria vuelve inmediatamente
 *      al control del recolector o ciclo de vida del cliente móvil.
 * ============================================================================
 */

extern "C" {
    #if defined(_WIN32)
        #define EXPORT_FFI __declspec(dllexport)
    #else
        #define EXPORT_FFI __attribute__((visibility("default")))
    #endif

    /**
     * @brief Cifra un voto binario mediante el esquema criptográfico de Paillier.
     * 
     * Formula de Paillier:
     *      c = (g^m * r^N) mod (N^2)
     * 
     * @param vote_str   Cadena representativa del voto plaintext ("0" o "1").
     * @param pub_n_str  Módulo público RSA/Paillier N (cadena decimal de alta precisión).
     * @param pub_g_str  Generador público g in Z*_{N^2} (comúnmente N + 1).
     * @param out_buffer Puntero al buffer preasignado por el llamador (Zero-Allocation).
     * @param max_len    Capacidad máxima en bytes del out_buffer para evitar Buffer Overflows.
     */
    EXPORT_FFI void encrypt_vote_ffi(
        const char* vote_str,
        const char* pub_n_str,
        const char* pub_g_str,
        char* out_buffer,
        int max_len
    ) {
        // Validación estricta de punteros y límites del buffer receptor
        if (!vote_str || !pub_n_str || !pub_g_str || !out_buffer || max_len <= 1) {
            return;
        }

        try {
            // 1. Instanciar enteros de precisión arbitraria usando gmpxx
            mpz_class m(vote_str);
            mpz_class n(pub_n_str);
            mpz_class g(pub_g_str);

            // 2. Calcular N^2 (módulo cuadrático del criptosistema de Paillier)
            mpz_class n_sq = n * n;

            // 3. Generación del factor de ofuscación pseudoaleatorio 'r'
            // En un entorno de producción móvil, 'r' debe obtenerse de una fuente de entropía
            // segura para hardware (/dev/urandom o getrandom(2)).
            // Para este prototipo funcional, derivamos un valor determinista y coprimo en Z*_N.
            mpz_class r = (n / 3) + 7919;
            mpz_class gcd_check;
            mpz_gcd(gcd_check.get_mpz_t(), r.get_mpz_t(), n.get_mpz_t());
            if (gcd_check != 1) {
                r = r + 1; // Corrección para asegurar coprimalidad: gcd(r, N) == 1
            }

            // 4. Exponenciaciones modulares de alta velocidad con GMP:
            // gm = (g^m) mod N^2
            mpz_class gm;
            mpz_powm(gm.get_mpz_t(), g.get_mpz_t(), m.get_mpz_t(), n_sq.get_mpz_t());

            // rn = (r^N) mod N^2
            mpz_class rn;
            mpz_powm(rn.get_mpz_t(), r.get_mpz_t(), n.get_mpz_t(), n_sq.get_mpz_t());

            // c = (gm * rn) mod N^2 (Texto Cifrado de Paillier)
            mpz_class c = (gm * rn) % n_sq;

            // 5. Generación simulada de Prueba de Conocimiento Cero (ZKP)
            // En votación verificable, esto certifica m in {0, 1} (Disjunctive Chaum-Pedersen ZKP)
            // sin revelar el bit del voto en texto plano.
            std::string simulated_zkp = "zkp_proof_paillier_v1_valid_vote_commitment_sha256_e4b29";

            // 6. Ensamblado del JSON de respuesta
            std::string c_str = c.get_str();
            std::ostringstream json_ss;
            json_ss << "{"
                    << "\"ciphertext\": \"" << c_str << "\", "
                    << "\"zkp\": \"" << simulated_zkp << "\""
                    << "}";

            std::string json_result = json_ss.str();

            // 7. Copia segura al buffer preasignado del host FFI (Zero-Allocation Pattern)
            size_t copy_len = json_result.length();
            if (copy_len >= static_cast<size_t>(max_len)) {
                copy_len = static_cast<size_t>(max_len - 1);
            }

            std::memcpy(out_buffer, json_result.data(), copy_len);
            out_buffer[copy_len] = '\0'; // Garantizar terminación nula segura

        } catch (const std::exception& ex) {
            // Manejo de excepciones criptográficas o parsing numérico inválido
            std::string err_payload = std::string("{\"error\": \"") + ex.what() + "\"}";
            size_t copy_len = err_payload.length();
            if (copy_len >= static_cast<size_t>(max_len)) {
                copy_len = static_cast<size_t>(max_len - 1);
            }
            std::memcpy(out_buffer, err_payload.data(), copy_len);
            out_buffer[copy_len] = '\0';
        }
    }
}
EOF

# ------------------------------------------------------------------------------
# 2. GENERACIÓN DEL TEST EN PYTHON FFI (test_ffi.py)
# ------------------------------------------------------------------------------
echo ">> [2/3] Generando test_ffi.py..."

cat << 'EOF' > test_ffi.py
#!/usr/bin/env python3
"""
Simulador de cliente móvil (Flutter / Dart FFI) utilizando Python ctypes.
Demuestra la invocación C ABI nativa y la transferencia de memoria sin asignación dinámica.
"""
import ctypes
import json
import os
import sys
import time

def main():
    lib_path = os.path.abspath("./libqoriproof.so")
    if not os.path.exists(lib_path):
        print(f"[-] Error: Biblioteca compartida no encontrada en {lib_path}")
        sys.exit(1)

    # 1. Cargar la librería compartida compilada en C++ nativo
    lib = ctypes.CDLL(lib_path)

    # 2. Definir la signatura C ABI equivalente a la esperada en Dart FFI:
    # typedef NativeEncryptVote = Void Function(
    #     Pointer<Utf8> vote,
    #     Pointer<Utf8> pubN,
    #     Pointer<Utf8> pubG,
    #     Pointer<Utf8> outBuffer,
    #     Int32 maxLen
    # );
    lib.encrypt_vote_ffi.argtypes = [
        ctypes.c_char_p,   # vote_str
        ctypes.c_char_p,   # pub_n_str
        ctypes.c_char_p,   # pub_g_str
        ctypes.c_char_p,   # out_buffer
        ctypes.c_int       # max_len
    ]
    lib.encrypt_vote_ffi.restype = None

    # 3. Preparación de parámetros criptográficos:
    # Voto: "1"
    vote_val = b"1"

    # Módulo Paillier N de 120 dígitos decimales (gran escala de seguridad)
    n_digits_120 = (
        "314159265358979323846264338327950288419716939937510582097494"
        "459230781640628620899862803482534211706798214808651328230664"
    )
    n_bytes = n_digits_120.encode('utf-8')

    # Generador g canónico de Paillier: g = N + 1
    g_val = str(int(n_digits_120) + 1)
    g_bytes = g_val.encode('utf-8')

    # 4. Zero-Allocation Bridge:
    # Preasignamos el buffer de memoria contigua en el cliente antes de invocar C++.
    # Capacidad de 4096 bytes: suficiente para N^2 (~240 dígitos) y campos ZKP JSON.
    BUFFER_CAPACITY = 4096
    out_buffer = ctypes.create_string_buffer(BUFFER_CAPACITY)

    print("======================================================================")
    print(" [QoriProof Mobile Cryptographic Bridge - Dart FFI Simulation]")
    print("======================================================================")
    print(f"[*] Entrada - Voto Plaintext : {vote_val.decode('utf-8')}")
    print(f"[*] Entrada - Módulo N ({len(n_digits_120)} dígitos): {n_digits_120[:32]}...{n_digits_120[-16:]}")
    print(f"[*] Buffer receptor asignado por el llamador : {BUFFER_CAPACITY} bytes")
    print("[*] Ejecutando cifrado de Paillier en núcleo C++ nativo...")

    # 5. Medición de latencia de cómputo nativo
    start_time = time.perf_counter()
    lib.encrypt_vote_ffi(vote_val, n_bytes, g_bytes, out_buffer, BUFFER_CAPACITY)
    end_time = time.perf_counter()

    latency_ms = (end_time - start_time) * 1000.0

    # 6. Decodificación y verificación del contenido escrito en memoria nativa
    raw_response = out_buffer.value.decode('utf-8')

    try:
        parsed_json = json.loads(raw_response)
    except json.JSONDecodeError as err:
        print(f"[-] Error al decodificar JSON devuelto: {err}")
        print(f"[-] Contenido crudo: {raw_response}")
        sys.exit(1)

    print("\n------------------------- REPORTE DE RESULTADOS ----------------------")
    print(f"[+] Estado de ejecución      : OK")
    print(f"[+] Latencia C++ Nativa       : {latency_ms:.3f} ms")
    print(f"[+] Longitud Texto Cifrado (c): {len(parsed_json.get('ciphertext', ''))} caracteres decimales")
    print("\n[+] JSON devuelto desde C++:")
    print(json.dumps(parsed_json, indent=2))
    print("======================================================================")

if __name__ == "__main__":
    main()
EOF

# ------------------------------------------------------------------------------
# 3. GENERACIÓN DEL DOCKERFILE
# ------------------------------------------------------------------------------
echo ">> [3/3] Generando Dockerfile..."

cat << 'EOF' > Dockerfile
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
EOF

# ------------------------------------------------------------------------------
# 4. CONSTRUCCIÓN Y EJECUCIÓN DEL CONTENEDOR DOCKER
# ------------------------------------------------------------------------------
echo "======================================================================"
echo ">> Construyendo la imagen Docker: qoriproof-env..."
echo "======================================================================"
docker build -t qoriproof-env .

echo "======================================================================"
echo ">> Ejecutando contenedor efímero para validar el puente FFI..."
echo "======================================================================"
docker run --rm qoriproof-env

echo "======================================================================"
echo " [QoriProof] Proceso completado exitosamente."
echo "======================================================================"
