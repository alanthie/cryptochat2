
#ifndef RSAGMPTest_h
#define RSAGMPTest_h

#include <iostream>
#include "RSAGMP.h"
#include <stdint.h>

namespace RSAGMP
{
    bool DefaultTest(unsigned int size = 1024, std::stringstream* serr = nullptr);
    bool CustomTest(unsigned int size, Utils::Generator *generator, int threads = 1, unsigned int precision=20, std::stringstream* serr = nullptr);
    bool CustomTest3(unsigned int size, Utils::Generator *generator, int threads = 1, unsigned int precision=20, std::stringstream* serr = nullptr);

    int main_rsa_gmp_test(unsigned int sz );

    int rsa_gmp_test_key(std::string n, std::string e, std::string d, unsigned int size, std::stringstream* serr = nullptr);


    bool get_keys(  unsigned int size, Utils::Generator *generator, int threads, unsigned int precision,
				    Utils::mpzBigInteger& pub, Utils::mpzBigInteger& priv, Utils::mpzBigInteger& modulus,
				    std::stringstream* serr = nullptr );

   bool get_keys_3primes(   unsigned int size, Utils::Generator *generator, int threads, unsigned int precision,
				            Utils::mpzBigInteger& pub, Utils::mpzBigInteger& priv, Utils::mpzBigInteger& modulus,
				            std::stringstream* serr = nullptr);

   bool get_keys_Nprimes(   unsigned int size, Utils::Generator *generator, int threads, unsigned int precision,
				            Utils::mpzBigInteger& pub, Utils::mpzBigInteger& priv, Utils::mpzBigInteger& modulus,
							unsigned int NPRIMES,
							std::stringstream* serr = nullptr);
}

#endif /* Test_h */
