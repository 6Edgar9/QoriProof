# QoriProof: Mobile Native Cryptographic Core

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++](https://img.shields.io/badge/Language-C%2B%2B17-blue.svg)](https://isocpp.org/)
[![GMP](https://img.shields.io/badge/Library-GNU%20GMP-orange.svg)](https://gmplib.org/)
[![Dart FFI](https://img.shields.io/badge/Interface-Dart%20FFI%20Compatible-0175C2.svg)](https://dart.dev/guides/libraries/c-interop)
[![Docker](https://img.shields.io/badge/Container-Ubuntu%2022.04-2496ED.svg)](https://www.docker.com/)

**QoriProof** es una librería criptográfica cliente escrita en **C++ nativo** de alto rendimiento, diseñada específicamente para ser embebida en aplicaciones móviles Flutter mediante **Dart FFI**. Su función principal es recibir un voto booleano en texto plano (`0` o `1`), cifrarlo en el dispositivo usando el criptosistema homomórfico aditivo de **Paillier** con aritmética multiprecisión **GNU GMP**, y generar una **Prueba de Conocimiento Cero (ZKP)** simulada, devolviendo un payload JSON estructurado.

Todo el cálculo criptográfico ocurre de forma aislada en el procesador nativo del dispositivo móvil, evitando la fuga de claves privadas o del voto fuera del dispositivo.

---

## Características Principales

- **Criptografía Homomórfica de Paillier**: Cifrado $c = (g^m \cdot r^N) \pmod{N^2}$ con enteros de precisión arbitraria vía `gmpxx`.
- **Arquitectura Zero-Allocation FFI**: Patrón *Caller-Allocated Buffer* para evitar fugas de memoria (*memory leaks*) o colisiones entre allocators de Dart VM y el heap de C++.
- **Latencia Ultrabaja**: Tiempos de cómputo en torno a **0.15 ms** para módulos de 120 dígitos decimales (~400 bits).
- **Compatibilidad C ABI**: Exportación limpia de funciones nativas compatibles con Dart FFI, Python ctypes, Swift/ObjC y JNI.
- **Entorno Contenerizado**: Script unificado de construcción y pruebas herméticas bajo Docker (Ubuntu 22.04).

---

## Estructura del Repositorio

```text
QoriProof/
├── .gitignore            # Reglas de exclusión para binarios, caches e IDEs
├── build_qoriproof.sh    # Script unificado Bash (orquestador de build y test)
├── Dockerfile            # Contenedor de compilación (g++, libgmp-dev, python3)
├── qoriproof.cpp         # Implementación C++ nativa (GMP + C ABI export)
├── test_ffi.py           # Arnés de prueba FFI con Python ctypes
├── CODE_EXPLANATION.md   # Explicación técnica exhaustiva de código y memoria
├── README.md             # Documentación principal del proyecto
└── LICENSE               # Licencia de código abierto MIT
```

---

## Arquitectura de Memoria Zero-Allocation

```text
+------------------------------------+          +------------------------------------+
|  Flutter (Dart VM / GC Managed)    |          |  QoriProof (C++ Nativo / GMP Core) |
+------------------------------------+          +------------------------------------+
|                                    |          |                                    |
| 1. calloc<Uint8>(4096)             |          |                                    |
|    (Preasigna buffer en cliente)   |          |                                    |
|                                    |          |                                    |
| 2. encrypt_vote_ffi(...)           |          |                                    |
|    Pasa: (vote, N, g, buf, 4096)   |  ======> | 3. Calcula c = (g^m * r^N) mod N^2 |
|                                    |          | 4. Genera JSON y zkp               |
|                                    |          | 5. std::memcpy seguro hacia buf    |
|                                    |  <====== |    (Límites acotados por max_len)  |
| 6. Convierte buf a Dart String     |          |                                    |
| 7. calloc.free(buf)                |          |                                    |
|    (Libera memoria bajo control)   |          |                                    |
+------------------------------------+          +------------------------------------+
```

Para una explicación matemática y de bajo nivel completa, consulta el documento **[CODE_EXPLANATION.md](CODE_EXPLANATION.md)**.

---

## Requisitos Previos

- **Docker** (Docker Desktop en Windows/macOS o Docker Engine en Linux).
- **Bash** (Linux, macOS, WSL2 o Git Bash en Windows).

---

## Inicio Rápido (Quickstart)

Ejecuta el script unificado de construcción y pruebas:

```bash
chmod +x build_qoriproof.sh
./build_qoriproof.sh
```

El script se encarga de:
1. Generar los archivos fuente `qoriproof.cpp`, `test_ffi.py` y `Dockerfile`.
2. Compilar la imagen Docker `qoriproof-env`.
3. Ejecutar el contenedor efímero (`docker run --rm`) validando la llamada C ABI y la latencia nativa.

### Salida Esperada

```text
======================================================================
 [QoriProof Mobile Cryptographic Bridge - Dart FFI Simulation]
======================================================================
[*] Entrada - Voto Plaintext : 1
[*] Entrada - Módulo N (120 dígitos): 31415926535897932384626433832795...4808651328230664
[*] Buffer receptor asignado por el llamador : 4096 bytes
[*] Ejecutando cifrado de Paillier en núcleo C++ nativo...

------------------------- REPORTE DE RESULTADOS ----------------------
[+] Estado de ejecución      : OK
[+] Latencia C++ Nativa       : 0.158 ms
[+] Longitud Texto Cifrado (c): 239 caracteres decimales

[+] JSON devuelto desde C++:
{
  "ciphertext": "81047839166172477502283127298605169893701793951927174487828340695310502150520814213926423562126968876292903857666591353724057225770040330183751820063430440000138515122988797657558232890072692892665507509961801722709314740703971137488534857",
  "zkp": "zkp_proof_paillier_v1_valid_vote_commitment_sha256_e4b29"
}
======================================================================
```

---

## Guía de Integración con Flutter (Dart FFI)

### 1. Definición de la Signatura FFI en Dart

```dart
import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';

// Tipo nativo en C ABI
typedef NativeEncryptVote = Void Function(
  Pointer<Utf8> voteStr,
  Pointer<Utf8> pubNStr,
  Pointer<Utf8> pubGStr,
  Pointer<Utf8> outBuffer,
  Int32 maxLen,
);

// Tipo equivalente en Dart
typedef DartEncryptVote = void Function(
  Pointer<Utf8> voteStr,
  Pointer<Utf8> pubNStr,
  Pointer<Utf8> pubGStr,
  Pointer<Utf8> outBuffer,
  int maxLen,
);
```

### 2. Invocación Segura Zero-Allocation

```dart
class QoriProofBridge {
  late final DynamicLibrary _lib;
  late final DartEncryptVote _encryptVote;

  QoriProofBridge() {
    _lib = Platform.isAndroid
        ? DynamicLibrary.open('libqoriproof.so')
        : DynamicLibrary.process();

    _encryptVote = _lib
        .lookup<NativeFunction<NativeEncryptVote>>('encrypt_vote_ffi')
        .asFunction<DartEncryptVote>();
  }

  String encryptVote({
    required String vote,
    required String pubN,
    required String pubG,
  }) {
    // 1. Convertir entradas a punteros UTF-8 nativos
    final pVote = vote.toNativeUtf8();
    final pPubN = pubN.toNativeUtf8();
    final pPubG = pubG.toNativeUtf8();

    // 2. Preasignar el buffer receptor (Caller-Allocated Buffer)
    const int bufferCapacity = 4096;
    final pOutBuffer = calloc<Uint8>(bufferCapacity).cast<Utf8>();

    try {
      // 3. Ejecución directa en C++
      _encryptVote(pVote, pPubN, pPubG, pOutBuffer, bufferCapacity);

      // 4. Lectura directa desde memoria nativa a String de Dart
      final resultJson = pOutBuffer.toDartString();
      return resultJson;
    } finally {
      // 5. Liberación garantizada de memoria preasignada
      calloc.free(pVote);
      calloc.free(pPubN);
      calloc.free(pPubG);
      calloc.free(pOutBuffer);
    }
  }
}
```

---

## Compilación Manual

Para compilar la biblioteca compartida de forma directa sin Docker (requiere `g++` y `libgmp-dev` instalados):

```bash
g++ -O3 -shared -fPIC qoriproof.cpp -lgmpxx -lgmp -o libqoriproof.so
python3 test_ffi.py
```

---

## Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.
