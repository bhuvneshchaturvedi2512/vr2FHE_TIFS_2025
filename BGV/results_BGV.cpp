#include "seal/seal.h"
#include <algorithm>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <cmath>

#include <chrono>

extern "C" {
    #include "sha256.c"
}

using namespace std;
using namespace seal;

char hex_ciphertextA[SHA256_HEX_SIZE];
char hex_ciphertextB[SHA256_HEX_SIZE];

char hex_Result[SHA256_HEX_SIZE];

char c_ciphertextA[524289];
char c_ciphertextB[524289];

char c_Result[524289];
char* c_Ciphertext;

int data_size = sizeof(uint64_t);

/*
Helper function: Convert a value into a hexadecimal string, e.g., uint64_t(17) --> "11".
*/
inline std::string uint64_to_hex_string(std::uint64_t value)
{
    return seal::util::uint_to_hex_string(&value, std::size_t(1));
}

char* concat(const char *s1, const char *s2, const char *s3)
{
    char *result = (char*)malloc(strlen(s1) + strlen(s2) + strlen(s3) + 1);
    strcpy(result, s1);
    strcat(result, s2);
    strcat(result, s3);
    return result;
}

char* concat_cipher(Ciphertext &sample)
{
	c_Ciphertext = (char*)malloc(8192*data_size + 1);
	char c_Temp[data_size + 1];
	snprintf(c_Ciphertext, data_size, "%lu", sample.data(1)[0]);
	for(int i = 1; i < 4096; ++i)
	{
		snprintf(c_Temp, data_size, "%lu", sample.data(1)[i]);
		strcat(c_Ciphertext, c_Temp);
	}
	for(int i = 0; i < 4096; ++i)
	{
		snprintf(c_Temp, data_size, "%lu", sample.data()[i]);
		strcat(c_Ciphertext, c_Temp);
	}
	return c_Ciphertext;
}

int main()
{

    srand(967);
    
    EncryptionParameters parms(scheme_type::bgv);

    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    parms.set_plain_modulus(1024);

    SEALContext context(parms);

    KeyGenerator keygen(context);
    
    cout << "Generating secret key ... ";
    
    SecretKey secret_key = keygen.secret_key();
    
    cout << " Done." << endl;
    
    cout << "Generating evaluation key ... this may take a while ... ";
    
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    
    cout << " Done.\n" << endl;

    Encryptor encryptor(context, public_key);

    Evaluator evaluator(context);

    Decryptor decryptor(context, secret_key);
    
    uint64_t x = rand()%4;
    uint64_t y = rand()%4;
    
    Plaintext x_plain(uint64_to_hex_string(x));
    Plaintext y_plain(uint64_to_hex_string(y));
    
    Ciphertext x_encrypted;
    Ciphertext y_encrypted;
    Ciphertext x_times_y;

    encryptor.encrypt(x_plain, x_encrypted);
    encryptor.encrypt(y_plain, y_encrypted);
    
    strcpy(c_ciphertextA, concat_cipher(x_encrypted));
    sha256_hex(c_ciphertextA, strlen(c_ciphertextA), hex_ciphertextA);
    	
    strcpy(c_ciphertextB, concat_cipher(y_encrypted));
    sha256_hex(c_ciphertextB, strlen(c_ciphertextB), hex_ciphertextB);
    
    double time_ADD_wo_hashing = 0.0;
    
    for(int i = 1; i <= 10; ++i)
    {
        auto start = chrono::high_resolution_clock::now();
    
        evaluator.add_inplace(x_encrypted, y_encrypted);
    
        auto end = chrono::high_resolution_clock::now();
    	
        chrono::duration<double> diff = end - start;
    
        time_ADD_wo_hashing = time_ADD_wo_hashing + diff.count();
    }
    
    time_ADD_wo_hashing = time_ADD_wo_hashing / 10.0;
    
    cerr << "Time required to run ADD gate without hash generation: " << time_ADD_wo_hashing << "s\n" << endl;
    
    double time_ADD_w_hashing = 0.0;
    
    for(int i = 1; i <= 10; ++i)
    {
        auto start = chrono::high_resolution_clock::now();
    
        evaluator.add_inplace(x_encrypted, y_encrypted);
    
        strcpy(c_Result, concat_cipher(x_encrypted));
        char *s_Result = concat(c_Result, hex_ciphertextA, hex_ciphertextB);
        sha256_hex(s_Result, strlen(s_Result), hex_Result);
    
        auto end = chrono::high_resolution_clock::now();
    	
        chrono::duration<double> diff = end - start;
    
        time_ADD_w_hashing = time_ADD_w_hashing + diff.count();
    }
    
    time_ADD_w_hashing = time_ADD_w_hashing / 10.0;
    
    cout << "Time required to run ADD gate with hash generation: " << time_ADD_w_hashing << "s\n" << endl;
    
    double diff_ADD_time = time_ADD_w_hashing - time_ADD_wo_hashing;
    double diff_ADD_percent = round(((diff_ADD_time/time_ADD_wo_hashing)*100)*10)/10.0;
    
    diff_ADD_time = diff_ADD_time > 0 ? diff_ADD_time : -diff_ADD_time;
    diff_ADD_percent = diff_ADD_percent > 0 ? diff_ADD_percent : -diff_ADD_percent;
    
    cerr << "Overhead introduced due to hashing in ADD: " << diff_ADD_time << "s or " << diff_ADD_percent <<"%\n" << endl;
    
    double time_MULT_wo_hashing = 0.0;
    
    for(int i = 1; i <= 10; ++i)
    {
        auto start = chrono::high_resolution_clock::now();
    
        evaluator.multiply(x_encrypted, y_encrypted, x_times_y);
        evaluator.relinearize_inplace(x_times_y, relin_keys);
    
        auto end = chrono::high_resolution_clock::now();
    	
        chrono::duration<double> diff = end - start;
    
        time_MULT_wo_hashing = time_MULT_wo_hashing + diff.count();
    }
    
    time_MULT_wo_hashing = time_MULT_wo_hashing / 10.0;
    
    cerr << "Time required to run MULT (with Relinearization) gate without hash generation: " << time_MULT_wo_hashing << "s\n" << endl;
    
    double time_MULT_w_hashing = 0.0;
    
    for(int i = 1; i <= 10; ++i)
    {
        auto start = chrono::high_resolution_clock::now();
    
        evaluator.multiply(x_encrypted, y_encrypted, x_times_y);
        evaluator.relinearize_inplace(x_times_y, relin_keys);
    
        strcpy(c_Result, concat_cipher(x_times_y));
        char *s_Result = concat(c_Result, hex_ciphertextA, hex_ciphertextB);
        sha256_hex(s_Result, strlen(s_Result), hex_Result);
    
        auto end = chrono::high_resolution_clock::now();
    	
        chrono::duration<double> diff = end - start;
    
        time_MULT_w_hashing = time_MULT_w_hashing + diff.count();
    }
    
    time_MULT_w_hashing = time_MULT_w_hashing / 10.0;
    
    cerr << "Time required to run MULT (with Relinearization) gate with hash generation: " << time_MULT_w_hashing << "s\n" << endl;
    
    double diff_MULT_time = time_MULT_w_hashing - time_MULT_wo_hashing;
    double diff_MULT_percent = round(((diff_MULT_time/time_MULT_wo_hashing)*100)*10)/10.0;
    
    diff_MULT_time = diff_MULT_time > 0 ? diff_MULT_time : -diff_MULT_time;
    diff_MULT_percent = diff_MULT_percent > 0 ? diff_MULT_percent : -diff_MULT_percent;
    	
    cerr << "Overhead introduced due to hashing in MULT: " << diff_MULT_time << "s or " << diff_MULT_percent <<"%\n" << endl;
    
    double diff_avg_time = (diff_ADD_time + diff_MULT_time) / 2.0;
    double diff_avg_percent = round(((diff_ADD_percent + diff_MULT_percent) / 2.0)*10)/10.0;
  	
    cerr << "Average increase in runtime due to hashing: " << diff_avg_time << "s or " << diff_avg_percent <<"%\n" << endl;
  	
}
