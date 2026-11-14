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
