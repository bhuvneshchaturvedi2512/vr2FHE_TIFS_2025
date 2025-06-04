#define _POSIX_C_SOURCE 200809L

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <chrono>
#include <iostream>

#include <cmath>

#include <chrono>

extern "C" {
    #include "sha256.c"
}

using namespace std;

TFheGateBootstrappingParameterSet* params;//TFHE parameters
TFheGateBootstrappingSecretKeySet* key;//secret key
const TFheGateBootstrappingCloudKeySet* bk;//bootstrapping key
LweSample* ciphertextA;
LweSample* ciphertextB;
LweSample* Result;

char hex_ciphertextA[SHA256_HEX_SIZE];
char hex_ciphertextB[SHA256_HEX_SIZE];

char hex_Result[SHA256_HEX_SIZE];

char c_ciphertextA[20193];
char c_ciphertextB[20193];

char c_Result[20193];
char* c_Ciphertext;

char* concat(const char *s1, const char *s2, const char *s3)
{
    char *result = (char*)malloc(strlen(s1) + strlen(s2) + strlen(s3) + 1);
    strcpy(result, s1);
    strcat(result, s2);
    strcat(result, s3);
    return result;
}

char* concat_cipher(LweSample* sample)
{
	c_Ciphertext = (char*)malloc(20193);
	char c_Temp[33];
	snprintf(c_Ciphertext, 32, "%u", sample->a[0]);
	for(int i = 1; i < 630; ++i)
	{
		snprintf(c_Temp, 32, "%u", sample->a[i]);
		strcat(c_Ciphertext, c_Temp);
		c_Temp[0] = '\0';
	}
	snprintf(c_Temp, 32, "%u", sample->b);
	strcat(c_Ciphertext, c_Temp);
	c_Temp[0] = '\0';
	return c_Ciphertext;
}

void delete_ciphertexts()
{
	//clean up all pointers
    	delete_gate_bootstrapping_ciphertext_array(1, Result);
    	delete_gate_bootstrapping_ciphertext_array(1, ciphertextA);
    	delete_gate_bootstrapping_ciphertext_array(1, ciphertextB);
}

double evaluate_without_hashing(int gate_index)
{
	int plaintext1,plaintext2;
  	plaintext1 = rand()%2;
  	plaintext2 = rand()%2;
  	
  	ciphertextA = new_gate_bootstrapping_ciphertext_array(1, params);
  	ciphertextB = new_gate_bootstrapping_ciphertext_array(1, params);

  	Result = new_gate_bootstrapping_ciphertext_array(1, params);
  
  	for (int j=0; j<1; j++) {
            bootsSymEncrypt(&ciphertextA[j], (plaintext1>>j)&1, key);
    	}
  	for (int j=0; j<1; j++) {
            bootsSymEncrypt(&ciphertextB[j], (plaintext2>>j)&1, key);
    	}
    	
    	std::chrono::duration<double> diff;
    	
    	switch(gate_index){
    	    
    	    case 0://NAND
    	           {
    	           	auto start = std::chrono::high_resolution_clock::now();
    	           	bootsNAND(Result, &ciphertextA[0], &ciphertextB[0], bk);
    	           	auto end = std::chrono::high_resolution_clock::now();
    	           	diff = end - start;
    	           	break;
    	           }
    	           
    	    case 1://AND
    	           {
    	           	auto start = std::chrono::high_resolution_clock::now();
    	           	bootsAND(Result, &ciphertextA[0], &ciphertextB[0], bk);
    	           	auto end = std::chrono::high_resolution_clock::now();
    	           	diff = end - start;
    	           	break;
    	           }
    	           
    	    case 2://NOR
    	           {
    	           	auto start = std::chrono::high_resolution_clock::now();
    	           	bootsNOR(Result, &ciphertextA[0], &ciphertextB[0], bk);
    	           	auto end = std::chrono::high_resolution_clock::now();
    	           	diff = end - start;
    	           	break;
    	           }
    	    case 3://OR
    	           {
    	           	auto start = std::chrono::high_resolution_clock::now();
    	           	bootsOR(Result, &ciphertextA[0], &ciphertextB[0], bk);
    	           	auto end = std::chrono::high_resolution_clock::now();
    	           	diff = end - start;
    	           	break;
    	           }
    	           
    	    case 4://XOR
    	           {
    	           	auto start = std::chrono::high_resolution_clock::now();
    	           	bootsXOR(Result, &ciphertextA[0], &ciphertextB[0], bk);
    	           	auto end = std::chrono::high_resolution_clock::now();
    	           	diff = end - start;
    	           	break;
    	           }
    	           
    	    case 5://XNOR
    	           {
    	           	auto start = std::chrono::high_resolution_clock::now();
    	           	bootsXNOR(Result, &ciphertextA[0], &ciphertextB[0], bk);
    	           	auto end = std::chrono::high_resolution_clock::now();
    	           	diff = end - start;
    	           	break;
    	           }
    	
    	}

    	return diff.count();
}

double evaluate_with_hashing(int gate_index)
{
	int plaintext1,plaintext2;
  	plaintext1 = rand()%2;
  	plaintext2 = rand()%2;
  	
  	ciphertextA = new_gate_bootstrapping_ciphertext_array(1, params);
  	ciphertextB = new_gate_bootstrapping_ciphertext_array(1, params);

  	Result = new_gate_bootstrapping_ciphertext_array(1, params);
  
  	for (int j=0; j<1; j++) {
            bootsSymEncrypt(&ciphertextA[j], (plaintext1>>j)&1, key);
    	}
  	for (int j=0; j<1; j++) {
            bootsSymEncrypt(&ciphertextB[j], (plaintext2>>j)&1, key);
    	}
    	
    	strcpy(c_ciphertextA, concat_cipher(ciphertextA));
    	sha256_hex(c_ciphertextA, strlen(c_ciphertextA), hex_ciphertextA);
    	
    	strcpy(c_ciphertextB, concat_cipher(ciphertextB));
    	sha256_hex(c_ciphertextB, strlen(c_ciphertextB), hex_ciphertextB);
    	
    	std::chrono::duration<double> diff;
    	
    	switch(gate_index){
    	    
    	    case 0://NAND
    	           {
    	           	auto start = std::chrono::high_resolution_clock::now();
    	           	bootsNAND(Result, &ciphertextA[0], &ciphertextB[0], bk);
    	           	strcpy(c_Result, concat_cipher(Result));
  	           	char *s_Result = concat(c_Result, hex_ciphertextA, hex_ciphertextB);
  	           	sha256_hex(s_Result, strlen(s_Result), hex_Result);
    	           	auto end = std::chrono::high_resolution_clock::now();
    	           	diff = end - start;
    	           	break;
    	           }
    	           
    	    case 1://AND
    	           {
    	           	auto start = std::chrono::high_resolution_clock::now();
    	           	bootsAND(Result, &ciphertextA[0], &ciphertextB[0], bk);
    	           	strcpy(c_Result, concat_cipher(Result));
  	           	char *s_Result = concat(c_Result, hex_ciphertextA, hex_ciphertextB);
  	           	sha256_hex(s_Result, strlen(s_Result), hex_Result);
    	           	auto end = std::chrono::high_resolution_clock::now();
    	           	diff = end - start;
    	           	break;
    	           }
    	           
    	    case 2://NOR
    	           {
    	           	auto start = std::chrono::high_resolution_clock::now();
    	           	bootsNOR(Result, &ciphertextA[0], &ciphertextB[0], bk);
    	           	strcpy(c_Result, concat_cipher(Result));
  	           	char *s_Result = concat(c_Result, hex_ciphertextA, hex_ciphertextB);
  	           	sha256_hex(s_Result, strlen(s_Result), hex_Result);
    	           	auto end = std::chrono::high_resolution_clock::now();
    	           	diff = end - start;
    	           	break;
    	           }
    	           
    	    case 3://OR
    	           {
    	           	auto start = std::chrono::high_resolution_clock::now();
    	           	bootsOR(Result, &ciphertextA[0], &ciphertextB[0], bk);
    	           	strcpy(c_Result, concat_cipher(Result));
  	           	char *s_Result = concat(c_Result, hex_ciphertextA, hex_ciphertextB);
  	           	sha256_hex(s_Result, strlen(s_Result), hex_Result);
    	           	auto end = std::chrono::high_resolution_clock::now();
    	           	diff = end - start;
    	           	break;
    	           }
    	           
    	    case 4://XOR
    	           {
    	           	auto start = std::chrono::high_resolution_clock::now();
    	           	bootsXOR(Result, &ciphertextA[0], &ciphertextB[0], bk);
    	           	strcpy(c_Result, concat_cipher(Result));
  	           	char *s_Result = concat(c_Result, hex_ciphertextA, hex_ciphertextB);
  	           	sha256_hex(s_Result, strlen(s_Result), hex_Result);
    	           	auto end = std::chrono::high_resolution_clock::now();
    	           	diff = end - start;
    	           	break;
    	           }
    	           
    	    case 5://XNOR
    	           {
    	           	auto start = std::chrono::high_resolution_clock::now();
    	           	bootsXNOR(Result, &ciphertextA[0], &ciphertextB[0], bk);
    	           	strcpy(c_Result, concat_cipher(Result));
  	           	char *s_Result = concat(c_Result, hex_ciphertextA, hex_ciphertextB);
  	           	sha256_hex(s_Result, strlen(s_Result), hex_Result);
    	           	auto end = std::chrono::high_resolution_clock::now();
    	           	diff = end - start;
    	           	break;
    	           }
    	
    	}

    	return diff.count();
}

int main(int argc, char *argv[]) {

  	srand(967); //srand(967); srand(1073); srand(2512); srand(2406); srand(2022); for testing.
  	
  	std::cout << "Setting up TFHE parameters\n";
  	
  	//generate a keyset
    	const int minimum_lambda = 110;
    	params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    	std::cout << "Generating keys ...\n";
    	
    	//generate a random key
    	uint32_t seed[] = { 723, 4093, 106 }; //uint32_t seed[] = { 723, 4093, 106 }; uint32_t seed[] = { 1, 10132, 494 }; uint32_t seed[] = { 11, 29, 37 }; uint32_t seed[] = { 2, 3, 5 }; uint32_t seed[] = { 101, 103, 107 };
    	tfhe_random_generator_setSeed(seed,3);
    	key = new_random_gate_bootstrapping_secret_keyset(params);
    	bk = &key->cloud;

    	double time_NAND_wo_hashing = 0.0;
    	
    	for(int i = 1; i <= 10; ++i)
    	{
    		time_NAND_wo_hashing = time_NAND_wo_hashing + evaluate_without_hashing(0);
    	}
    	
    	time_NAND_wo_hashing = time_NAND_wo_hashing / 10.0;

  	cerr << "Time required to run NAND gate without hash generation: " << time_NAND_wo_hashing << "s\n" << endl;
  	
    	double time_NAND_w_hashing = 0.0;
    	
    	for(int i = 1; i <= 10; ++i)
    	{
    		time_NAND_w_hashing = time_NAND_w_hashing + evaluate_with_hashing(0);
    	}
    	
    	time_NAND_w_hashing = time_NAND_w_hashing / 10.0;

  	cerr << "Time required to run NAND gate with hash generation: " << time_NAND_w_hashing << "s\n" << endl;
  	
  	double diff_NAND_time = time_NAND_w_hashing - time_NAND_wo_hashing;
  	double diff_NAND_percent = round(((diff_NAND_time/time_NAND_wo_hashing)*100)*10)/10.0;
  	
  	diff_NAND_time = diff_NAND_time > 0 ? diff_NAND_time : -diff_NAND_time;
  	diff_NAND_percent = diff_NAND_percent > 0 ? diff_NAND_percent : -diff_NAND_percent;
  	
  	cerr << "Overhead introduced due to hashing in NAND: " << diff_NAND_time << "s or " << diff_NAND_percent <<"%\n" << endl;
  	
    	double time_AND_wo_hashing = 0.0;
    	
    	for(int i = 1; i <= 10; ++i)
    	{
    		time_AND_wo_hashing = time_AND_wo_hashing + evaluate_without_hashing(1);
    	}
    	
    	time_AND_wo_hashing = time_AND_wo_hashing / 10.0;

  	cerr << "Time required to run AND gate without hash generation: " << time_AND_wo_hashing << "s\n" << endl;
  	
    	double time_AND_w_hashing = 0.0;
    	
    	for(int i = 1; i <= 10; ++i)
    	{
    		time_AND_w_hashing = time_AND_w_hashing + evaluate_with_hashing(1);
    	}
    	
    	time_AND_w_hashing = time_AND_w_hashing / 10.0;

  	cerr << "Time required to run AND gate with hash generation: " << time_AND_w_hashing << "s\n" << endl;
  	
  	double diff_AND_time = time_AND_w_hashing - time_AND_wo_hashing;
  	double diff_AND_percent = round(((diff_AND_time/time_AND_wo_hashing)*100)*10)/10.0;
  	
  	diff_AND_time = diff_AND_time > 0 ? diff_AND_time : -diff_AND_time;
  	diff_AND_percent = diff_AND_percent > 0 ? diff_AND_percent : -diff_AND_percent;
  	
  	cerr << "Overhead introduced due to hashing in AND: " << diff_AND_time << "s or " << diff_AND_percent <<"%\n" << endl;
  	
    	double time_NOR_wo_hashing = 0.0;
    	
    	for(int i = 1; i <= 10; ++i)
    	{
    		time_NOR_wo_hashing = time_NOR_wo_hashing + evaluate_without_hashing(2);
    	}
    	
    	time_NOR_wo_hashing = time_NOR_wo_hashing / 10.0;

  	cerr << "Time required to run NOR gate without hash generation: " << time_NOR_wo_hashing << "s\n" << endl;
  	
    	double time_NOR_w_hashing = 0.0;
    	
    	for(int i = 1; i <= 10; ++i)
    	{
    		time_NOR_w_hashing = time_NOR_w_hashing + evaluate_with_hashing(2);
    	}
    	
    	time_NOR_w_hashing = time_NOR_w_hashing / 10.0;

  	cerr << "Time required to run NOR gate with hash generation: " << time_NOR_w_hashing << "s\n" << endl;
  	
  	double diff_NOR_time = time_NOR_w_hashing - time_NOR_wo_hashing;
  	double diff_NOR_percent = round(((diff_NOR_time/time_NOR_wo_hashing)*100)*10)/10.0;
  	
  	diff_NOR_time = diff_NOR_time > 0 ? diff_NOR_time : -diff_NOR_time;
  	diff_NOR_percent = diff_NOR_percent > 0 ? diff_NOR_percent : -diff_NOR_percent;
  	
  	cerr << "Overhead introduced due to hashing in NOR: " << diff_NOR_time << "s or " << diff_NOR_percent <<"%\n" << endl;
  	
    	double time_OR_wo_hashing = 0.0;
    	
    	for(int i = 1; i <= 10; ++i)
    	{
    		time_OR_wo_hashing = time_OR_wo_hashing + evaluate_without_hashing(3);
    	}
    	
    	time_OR_wo_hashing = time_OR_wo_hashing / 10.0;

  	cerr << "Time required to run OR gate without hash generation: " << time_OR_wo_hashing << "s\n" << endl;
  	
    	double time_OR_w_hashing = 0.0;
    	
    	for(int i = 1; i <= 10; ++i)
    	{
    		time_OR_w_hashing = time_OR_w_hashing + evaluate_with_hashing(3);
    	}
    	
    	time_OR_w_hashing = time_OR_w_hashing / 10.0;

  	cerr << "Time required to run OR gate with hash generation: " << time_OR_w_hashing << "s\n" << endl;
  	
  	double diff_OR_time = time_OR_w_hashing - time_OR_wo_hashing;
  	double diff_OR_percent = round(((diff_OR_time/time_OR_wo_hashing)*100)*10)/10.0;
  	
  	diff_OR_time = diff_OR_time > 0 ? diff_OR_time : -diff_OR_time;
  	diff_OR_percent = diff_OR_percent > 0 ? diff_OR_percent : -diff_OR_percent;
  	
  	cerr << "Overhead introduced due to hashing in OR: " << diff_OR_time << "s or " << diff_OR_percent <<"%\n" << endl;
  	
    	double time_XOR_wo_hashing = 0.0;
    	
    	for(int i = 1; i <= 10; ++i)
    	{
    		time_XOR_wo_hashing = time_XOR_wo_hashing + evaluate_without_hashing(4);
    	}
    	
    	time_XOR_wo_hashing = time_XOR_wo_hashing / 10.0;

  	cerr << "Time required to run XOR gate without hash generation: " << time_XOR_wo_hashing << "s\n" << endl;
  	
    	double time_XOR_w_hashing = 0.0;
    	
    	for(int i = 1; i <= 10; ++i)
    	{
    		time_XOR_w_hashing = time_XOR_w_hashing + evaluate_with_hashing(4);
    	}
    	
    	time_XOR_w_hashing = time_XOR_w_hashing / 10.0;

  	cerr << "Time required to run XOR gate with hash generation: " << time_XOR_w_hashing << "s\n" << endl;
  	
  	double diff_XOR_time = time_XOR_w_hashing - time_XOR_wo_hashing;
  	double diff_XOR_percent = round(((diff_XOR_time/time_XOR_wo_hashing)*100)*10)/10.0;
  	
  	diff_XOR_time = diff_XOR_time > 0 ? diff_XOR_time : -diff_XOR_time;
  	diff_XOR_percent = diff_XOR_percent > 0 ? diff_XOR_percent : -diff_XOR_percent;
  	
  	cerr << "Overhead introduced due to hashing in XOR: " << diff_XOR_time << "s or " << diff_XOR_percent <<"%\n" << endl;
  	
    	double time_XNOR_wo_hashing = 0.0;
    	
    	for(int i = 1; i <= 10; ++i)
    	{
    		time_XNOR_wo_hashing = time_XNOR_wo_hashing + evaluate_without_hashing(5);
    	}
    	
    	time_XNOR_wo_hashing = time_XNOR_wo_hashing / 10.0;

  	cerr << "Time required to run XNOR gate without hash generation: " << time_XNOR_wo_hashing << "s\n" << endl;
  	
    	double time_XNOR_w_hashing = 0.0;
    	
    	for(int i = 1; i <= 10; ++i)
    	{
    		time_XNOR_w_hashing = time_XNOR_w_hashing + evaluate_with_hashing(5);
    	}
    	
    	time_XNOR_w_hashing = time_XNOR_w_hashing / 10.0;

  	cerr << "Time required to run XNOR gate with hash generation: " << time_XNOR_w_hashing << "s\n" << endl;
  	
  	double diff_XNOR_time = time_XNOR_w_hashing - time_XNOR_wo_hashing;
  	double diff_XNOR_percent = round(((diff_XNOR_time/time_XNOR_wo_hashing)*100)*10)/10.0;
  	
  	diff_XNOR_time = diff_XNOR_time > 0 ? diff_XNOR_time : -diff_XNOR_time;
  	diff_XNOR_percent = diff_XNOR_percent > 0 ? diff_XNOR_percent : -diff_XNOR_percent;
  	
  	cerr << "Overhead introduced due to hashing in XOR: " << diff_XOR_time << "s or " << diff_XOR_percent <<"%\n" << endl;
  	
  	double diff_avg_time = (diff_NAND_time + diff_AND_time + diff_NOR_time + diff_OR_time + diff_XOR_time + diff_XNOR_time) / 6.0;
  	double diff_avg_percent = round(((diff_NAND_percent + diff_AND_percent + diff_NOR_percent + diff_OR_percent + diff_XOR_percent + diff_XNOR_percent) / 6.0)*10)/10.0;
  	
  	cerr << "Average increase in runtime due to hashing: " << diff_avg_time << "s or " << diff_avg_percent <<"%\n" << endl;
  	
    	//clean up all pointers
    	delete_gate_bootstrapping_secret_keyset(key);
    	delete_gate_bootstrapping_parameters(params);
}


