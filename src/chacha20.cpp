/**
 * 
 * Author: Eric Dürr Sierra | eric.durr.20@ull.edu.es
 * 
 * Created: 01/03/2021
 * Modified: 01/03/2021
 * 
 * 
 */

#include <iostream>
#include <regex>
#include "../include/chacha20.h"
int main()
{

    std::vector<std::string> in = {
        "61707865", "3320646e", "79622d32", "6b206574", // palabras
        "00010203", "04050607", "08090a0b", "0c0d0e0f", // clave
        "10111213", "14151617", "18191a1b", "1c1d1e1f", // clave
        "01000000", "00000009", "0000004a", "00000000"  //contador y nonce
    };
    std::vector<std::string> out;

    std::cout << "\nEstado previo al generador = " << std::endl;
    std::cout << strings_to_string(in) << "\n";
    in = reverse_set(in, BASE, OFFSET);
    out = chacha_block(out, in, ROUNDS);

    std::cout << "\nEstado de salida del generador = " << std::endl;
    std::cout << strings_to_string(out) << "\n";
}