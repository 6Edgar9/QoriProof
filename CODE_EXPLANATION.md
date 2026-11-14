# Explicación Técnica y Arquitectura de Código: QoriProof

Este documento detalla los fundamentos matemáticos, decisiones de ingeniería de software, gestión de memoria nativa y mecanismos FFI implementados en el núcleo criptográfico **QoriProof**.

---

## 1. Fundamentos Criptográficos: Criptosistema de Paillier

El criptosistema de Paillier es un esquema asimétrico probabilístico que cuenta con la propiedad de **homomorfismo aditivo**. Permite que entidades externas agreguen votos cifrados sin descifrar individualmente la elección de cada votante:

$$\mathcal{D}(c_1 \cdot c_2 \pmod{N^2}) = (m_1 + m_2) \pmod N$$

### 1.1 Parámetros Públicos
- $N = p \cdot q$: Módulo RSA producto de dos primos grandes.
- $N^2$: Espacio del texto cifrado ($\mathbb{Z}^*_{N^2}$).
- $g \in \mathbb{Z}^*_{N^2}$: Generador (típicamente $g = N + 1$ en implementaciones optimizadas).

### 1.2 Proceso de Cifrado
Para un mensaje $m \in \{0, 1\}$ (voto booleano):
1. Se selecciona un factor de ofuscación aleatorio $r \in \mathbb{Z}^*_N$ tal que $\gcd(r, N) = 1$.
2. Se calcula el texto cifrado $c$:
   $$c = \left( g^m \cdot r^N \right) \pmod{N^2}$$

### 1.3 Prueba de Conocimiento Cero (ZKP)
En un sistema electoral seguro, el votante debe demostrar que su voto $m$ pertenece estrictamente al conjunto $\{0, 1\}$ sin revelar el valor de $m$. Esto se realiza mediante una prueba disyuntiva de Chaum-Pedersen (Disjunctive Zero-Knowledge Proof). En este prototipo cliente, el hash y estructura de la prueba son sintetizados en la salida JSON para acoplamiento con verificadores externos.

---

## 2. Gestión de Memoria Nativa y C ABI (Zero-Allocation FFI)

### 2.1 El Problema del Heap Cruzado (Cross-Runtime Allocations)
Cuando un lenguaje gestionado como Dart (Flutter VM) o Python interactúa con C++ a través de FFI, existen dos runtimes con manejadores de memoria distintos:
- **Dart VM / GC**: Administra memoria basada en generational garbage collection.
- **C++ Runtime (glibc / bionic / libc++)**: Gestiona asignaciones en el heap del sistema operativo vía `malloc` / `free`.

Si la función nativa en C++ asignara memoria con `malloc` o `new` y devolviera un puntero crudo (`char*`):
1. **Fuga de Memoria (Leak)**: El GC de Dart no puede liberar automáticamente punteros nativos sin un `NativeFinalizer`.
2. **Crash por Desasignación Inválida**: Si Dart intentara liberar dicho puntero con su propio allocator, o si C++ usara un runtime con versión de libc distinta, el programa colapsa con `SIGSEGV` o corrupción de heap.

### 2.2 Patrón de Diseño: "Caller-Allocated Buffer"
QoriProof implementa el patrón de buffer preasignado por el llamador:

```text
[ Cliente: Flutter / Dart ]                         [ Núcleo Nativo: C++ ]
           |                                                  |
           |  1. Preasigna buffer contiguo en memoria          |
           |     Pointer<Utf8> buf = calloc<Uint8>(4096)      |
           |                                                  |
           |  2. Invocación FFI: (vote, N, g, buf, 4096)      |
           |------------------------------------------------->|
           |                                                  | 3. Opera en registros / pila
           |                                                  | 4. std::memcpy seguro a buf
           |                                                  | 5. Garantiza terminación nula '\0'
           |<-------------------------------------------------|
           |  6. Retorno void (Cero punteros nuevos huérfanos)|
           |                                                  |
           |  7. Lee resultado string directamente de buf     |
           |  8. Libera buf con calloc.free()                 |
           v                                                  v
```

Ventajas:
- **Cero fugas de memoria**: El ciclo de vida del buffer pertenece enteramente al cliente.
- **Protección contra desbordamientos (Buffer Overflow)**: El parámetro `max_len` restringe la copia (`std::memcpy`) previniendo accesos fuera de límites.
- **Determinismo**: No hay pausas por desfragmentación de heap en el lado C++.

---

## 3. Análisis Detallado del Código Fuente

### 3.1 `qoriproof.cpp`

```cpp
#include <gmpxx.h>
#include <string>
#include <cstring>
#include <iostream>
#include <sstream>
```
- `<gmpxx.h>`: Proporciona la interfaz C++ orientada a objetos (`mpz_class`) sobre la biblioteca GNU Multiple Precision Arithmetic Library (GMP), optimizada en ensamblador para operaciones criptográficas de enteros gigantes.
- `<cstring>`: Utilizado para operaciones de memoria de bajo nivel acotadas (`std::memcpy`).

#### Exportación C ABI
```cpp
extern "C" {
    #if defined(_WIN32)
        #define EXPORT_FFI __declspec(dllexport)
    #else
        #define EXPORT_FFI __attribute__((visibility("default")))
    #endif

    EXPORT_FFI void encrypt_vote_ffi(
        const char* vote_str,
        const char* pub_n_str,
        const char* pub_g_str,
        char* out_buffer,
        int max_len
    )
```
- `extern "C"`: Desactiva el *name mangling* de C++, permitiendo que los símbolos sean resueltos por Dart FFI o Python `ctypes` con su nombre exacto.
- `EXPORT_FFI`: Configura los atributos de visibilidad dinámica del linker (para ELF en Linux/Android y PE/COFF en Windows).

#### Lógica Criptográfica con GMP
```cpp
mpz_class m(vote_str);
mpz_class n(pub_n_str);
mpz_class g(pub_g_str);
mpz_class n_sq = n * n;
```
- Conversión transparente de cadenas en base 10 a representaciones multiprecisión de GMP.
- Cálculo de $N^2$. Con $N$ de 120 dígitos (~400 bits), $N^2$ contiene aproximadamente 240 dígitos (~800 bits).

```cpp
mpz_powm(gm.get_mpz_t(), g.get_mpz_t(), m.get_mpz_t(), n_sq.get_mpz_t());
mpz_powm(rn.get_mpz_t(), r.get_mpz_t(), n.get_mpz_t(), n_sq.get_mpz_t());
mpz_class c = (gm * rn) % n_sq;
```
- `mpz_powm`: Ejecuta la exponenciación modular $b^e \pmod m$ en tiempo logarítmico mediante reducción de Montgomery o división binaria acelerada en hardware.
- El texto cifrado final $c$ se obtiene de la multiplicación modular en $\mathbb{Z}^*_{N^2}$.

#### Formateo y Copia Segura
```cpp
size_t copy_len = json_result.length();
if (copy_len >= static_cast<size_t>(max_len)) {
    copy_len = static_cast<size_t>(max_len - 1);
}
std::memcpy(out_buffer, json_result.data(), copy_len);
out_buffer[copy_len] = '\0';
```
- Previene sobreescrituras en caso de que el tamaño del JSON exceda la capacidad del buffer.
- Fuerza el byte de terminación nula (`\0`) en la posición final válida.

---

### 3.2 `test_ffi.py` (Simulador de Dart FFI)

El script de Python replica con fidelidad el comportamiento de memoria que ejecutará el motor de Flutter:
1. **Carga dinámica**: `ctypes.CDLL("./libqoriproof.so")`.
2. **Definición de tipos de entrada**: Argumentos `c_char_p` para los punteros de cadenas UTF-8.
3. **Preasignación de buffer receptor**: `ctypes.create_string_buffer(4096)`.
4. **Métricas de rendimiento**: Uso de `time.perf_counter()` de alta resolución para certificar la latencia de cómputo en microsegundos.

---

### 3.3 `Dockerfile`

El contenedor Docker garantiza un entorno hermético y reproducible:
```dockerfile
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ make libgmp-dev python3 && rm -rf /var/lib/apt/lists/*
COPY qoriproof.cpp test_ffi.py /app/
RUN g++ -O3 -shared -fPIC qoriproof.cpp -lgmpxx -lgmp -o libqoriproof.so
CMD ["python3", "test_ffi.py"]
```
- `-O3`: Nivel de optimización máxima de GCC (vectorización, loop unrolling e inlining).
- `-shared`: Genera una biblioteca dinámica (.so).
- `-fPIC`: Genera *Position Independent Code*, requisito indispensable para bibliotecas compartidas cargadas en espacio de direcciones aleatorizado (ASLR).
- `-lgmpxx -lgmp`: Enlace dinámico con la biblioteca matemática GNU MP.

---

### 3.4 `build_qoriproof.sh`

Script orquestador unificado con directivas de seguridad Bash:
- `set -euo pipefail`: Detiene inmediatamente la ejecución si cualquier comando falla o se usa una variable no inicializada.
- `cat << 'EOF'`: Inyección literal de código fuente sin expansión accidental de variables de entorno de shell.
- Automatiza el ciclo completo: creación de archivos -> build de imagen -> ejecución de contenedor efímero (`docker run --rm`).
