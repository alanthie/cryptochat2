#include "RSAGMPTest.h"
#include <sstream>

bool RSAGMP::DefaultTest(unsigned int size, std::stringstream* serr)
{
   auto start = std::chrono::high_resolution_clock::now();

   if(size < 64)
   {
       if (serr!=nullptr) (*serr) << "RSA test invald input, need >= 64\n";
       return false;
   }
   mpzBigInteger pub, priv, modulus;
   Utils::TestGenerator generator;
   Keygen(pub, priv, modulus, &generator, size);
   mpzBigInteger message = generator.getBig(size) % modulus;
   mpzBigInteger crypto = Encrypt(message, pub, modulus);
   mpzBigInteger message1 = Decrypt(crypto, priv, modulus);

   auto finish = std::chrono::high_resolution_clock::now();
   std::chrono::duration<double, std::milli> elapsed = finish - start;

   bool result = (message1 == message);
   if(result)
       if (serr!=nullptr) (*serr)  << "RSA GMP encrypt/decrypt OK - bits size: " << std::to_string(size) << " - Elapsed Time: " << elapsed.count() / 1000 << " sec" << std::endl;
   else
       if (serr!=nullptr) (*serr)  << "ERROR RSA GMP encrypt/decrypt\n";
   return result;
}

int RSAGMP::rsa_gmp_test_key(std::string n, std::string e,std::string d, unsigned int size, std::stringstream* serr)
{
   mpzBigInteger modulus(n);
   mpzBigInteger pub(e);
   mpzBigInteger priv(d);

   Utils::TestGenerator generator;

   mpzBigInteger message = generator.getBig(size) % modulus;
   mpzBigInteger crypto = Encrypt(message, pub, modulus);
   mpzBigInteger message1 = Decrypt(crypto, priv, modulus);
   bool result = message1 == message;

   if(result)
   {
       if (serr!=nullptr) (*serr) << "RSA GMP encrypt/decrypt OK\n";
       return 0;
   }
   else
   {
       if (serr!=nullptr) (*serr) << "RSA GMP encrypt/decrypt ERROR\n";
       return -1;
   }
}

bool RSAGMP::CustomTest(unsigned int size, Utils::Generator *generator, int threads, unsigned int precision,
                        std::stringstream* serr)
{
auto start = std::chrono::high_resolution_clock::now();

   if(size < 64 || generator == NULL)
   {
       if (serr!=nullptr) (*serr)  << "RSA test invalid input, need >= 64\n";
       return false;
   }
   mpzBigInteger pub, priv, modulus;

   ParallelKeygen(pub, priv, modulus, generator, size, threads, precision);
   mpzBigInteger message = generator->getBig(size) % modulus;
   mpzBigInteger crypto = Encrypt(message, pub, modulus);
   mpzBigInteger message1 = Decrypt(crypto, priv, modulus);
   bool result = message1 == message;

   auto finish = std::chrono::high_resolution_clock::now();
   std::chrono::duration<double, std::milli> elapsed = finish - start;

   if(result)
        if (serr!=nullptr) (*serr) << "RSA GMP  Encrypt/Decrypt OK- bits size: " << std::to_string(size) << " - Elapsed Time: " << elapsed.count() / 1000 << " sec" << std::endl;
   else
        if (serr!=nullptr) (*serr) << "ERROR RSA GMP Encrypt/Decrypt\n";
   return result;
}

bool RSAGMP::CustomTest3(unsigned int size, Utils::Generator *generator, int threads, unsigned int precision,
                            std::stringstream* serr)
{
	auto start = std::chrono::high_resolution_clock::now();

   if(size < 96 || generator == NULL)
   {
       if (serr!=nullptr) (*serr) << "RSA test invalid input, bits size must be >= 96\n";
       return false;
   }
   mpzBigInteger pub, priv, modulus;

   ParallelKeygen3(pub, priv, modulus, generator, size, threads, precision);
   mpzBigInteger message = generator->getBig(size) % modulus;
   mpzBigInteger crypto = Encrypt(message, pub, modulus);
   mpzBigInteger message1 = Decrypt(crypto, priv, modulus);
   bool result = message1 == message;

   auto finish = std::chrono::high_resolution_clock::now();
   std::chrono::duration<double, std::milli> elapsed = finish - start;

   if(result)
       if (serr!=nullptr) (*serr)  << "RSA GMP Encrypt/Decrypt OK- bits size: " << std::to_string(size) << " - Elapsed Time: " << elapsed.count() / 1000 << " sec" << std::endl;
   else
 		if (serr!=nullptr) (*serr) << "ERROR RSA GMP Encrypt/Decrypt\n";
   return result;
}

bool RSAGMP::get_keys(	unsigned int size, Utils::Generator *generator, int threads, unsigned int precision,
						Utils::mpzBigInteger& pub, Utils::mpzBigInteger& priv, Utils::mpzBigInteger& modulus,
						std::stringstream* serr)
{
	auto start = std::chrono::high_resolution_clock::now();

	if(size < 64 || generator == NULL)
	{
        if (serr!=nullptr) (*serr) << "RSA  invalid input, bit size must be >= 64 bits\n";
		return false;
	}

	ParallelKeygen(pub, priv, modulus, generator, size, threads, precision);
	mpzBigInteger message = generator->getBig(size) % modulus;
	mpzBigInteger crypto = Encrypt(message, pub, modulus);
	mpzBigInteger message1 = Decrypt(crypto, priv, modulus);
	bool result = message1 == message;

	auto finish = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double, std::milli> elapsed = finish - start;

	if(result)
		if (serr!=nullptr) (*serr) << "RSA GMP Encrypt/Decrypt OK- bits size: " << std::to_string(size) << " - Elapsed Time: " << elapsed.count() / 1000 << " sec" << std::endl;
	else
		if (serr!=nullptr) (*serr)  << "ERROR RSA GMP Encrypt/Decrypt\n";

	return result;
}

bool RSAGMP::get_keys_3primes(	unsigned int size, Utils::Generator *generator, int threads, unsigned int precision,
								Utils::mpzBigInteger& pub, Utils::mpzBigInteger& priv, Utils::mpzBigInteger& modulus,
								std::stringstream* serr)
{
	auto start = std::chrono::high_resolution_clock::now();

	if(size < 32*3 || generator == NULL)
	{
		if (serr!=nullptr) (*serr)  << "RSA (3 primes) invalid input, bit size must be >= 96 bits\n";
		return false;
	}

	ParallelKeygen3(pub, priv, modulus, generator, size, threads, precision);
	mpzBigInteger message = generator->getBig(size) % modulus;
	mpzBigInteger crypto = Encrypt(message, pub, modulus);
	mpzBigInteger message1 = Decrypt(crypto, priv, modulus);
	bool result = message1 == message;

	auto finish = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double, std::milli> elapsed = finish - start;

	if(result) if (serr!=nullptr) (*serr) << "RSA (3 primes) GMP Encrypt/Decrypt OK- bits size: " << std::to_string(size) << " - Elapsed Time: " << elapsed.count() / 1000 << " sec" << std::endl;
	else if (serr!=nullptr) (*serr)  << "ERROR RSA (3 primes) GMP Encrypt/Decrypt\n";

	return result;
}

bool RSAGMP::get_keys_Nprimes(	unsigned int size, Utils::Generator *generator, int threads, unsigned int precision,
								Utils::mpzBigInteger& pub, Utils::mpzBigInteger& priv, Utils::mpzBigInteger& modulus,
								unsigned int NPRIMES,
								std::stringstream* serr)
{
	auto start = std::chrono::high_resolution_clock::now();

	if ((size < 32*NPRIMES) || (generator == NULL))
	{
		if (serr!=nullptr) (*serr)  << "RSA (N primes) invalid input, bit size must be >= 32*NPRIMES bits\n";
		return false;
	}

	ParallelKeygenN(pub, priv, modulus, generator, size, threads, precision, NPRIMES);
	mpzBigInteger message = generator->getBig(size) % modulus;
	mpzBigInteger crypto = Encrypt(message, pub, modulus);
	mpzBigInteger message1 = Decrypt(crypto, priv, modulus);
	bool result = message1 == message;

	auto finish = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double, std::milli> elapsed = finish - start;

	if(result) if (serr!=nullptr) (*serr) << "RSA (N primes) GMP Encrypt/Decrypt OK- bits size: " << std::to_string(size) << " - Elapsed Time: " << elapsed.count() / 1000 << " sec" << std::endl;
	else if (serr!=nullptr) (*serr) << "ERROR RSA (N primes) GMP Encrypt/Decrypt\n";

	return result;
}
