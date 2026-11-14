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
