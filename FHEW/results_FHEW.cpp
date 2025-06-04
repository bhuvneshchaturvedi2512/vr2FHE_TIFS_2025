#include <iostream>
#include <cstdlib>
#include <string.h>
#include <stdlib.h>
#include "LWE.h"
#include "FHEW.h"
#include "distrib.h"

#include <cmath>

#include <chrono>

extern "C" {
    #include "sha256.c"
}

using namespace std;

void help(char* cmd) {
  cerr << "\nusage: " << cmd << " n\n\n" 
  << "  Generate a secret key sk and evaluation key ek, and repeat the following test n times:\n"
  << "   - generate random bits b1,b2,b3,b4\n"
  << "   - compute ciphertexts c1, c2, c3 and c4 encrypting b1, b2, b3 and b4  under sk\n"
  << "   - homomorphically compute the encrypted (c1 NAND c2) NAND (c3 NAND c4) \n"
  << "   - decrypt all the intermediate results and check correctness \n"
  << "\n If any of the tests fails, print ERROR and stop immediately.\n\n";
  exit(0);
}

int cleartext_gate(int v1, int v2, BinGate gate){
  switch(gate)
  {
    case OR: return v1 || v2;
    case AND: return v1 && v2;
    case NOR: return not(v1 || v2);
    case NAND: return not(v1 && v2);
    default: cerr << "\n This gate does not exists \n"; exit(1); return 0;
  }
}

void cerr_gate(BinGate gate){
  switch(gate)
  {
    case OR: cerr << " OR\t"; return;
    case AND: cerr << " AND\t"; return;
    case NOR: cerr << " NOR\t"; return;
    case NAND: cerr << " NAND\t"; return;
  }
}

LWE::SecretKey LWEsk;
FHEW::EvalKey EK;
LWE::CipherText ciphertextA, ciphertextB, Result;

char hex_ciphertextA[SHA256_HEX_SIZE];
char hex_ciphertextB[SHA256_HEX_SIZE];

char hex_Result[SHA256_HEX_SIZE];

char c_ciphertextA[16033];
char c_ciphertextB[16033];

char c_Result[16033];
char* c_Ciphertext;

char* concat(const char *s1, const char *s2, const char *s3)
{
    char *result = (char*)malloc(strlen(s1) + strlen(s2) + strlen(s3) + 1);
    strcpy(result, s1);
    strcat(result, s2);
    strcat(result, s3);
    return result;
}

char* concat_cipher(LWE::CipherText sample)
{
	c_Ciphertext = (char*)malloc(16033);
	char c_Temp[33];
	snprintf(c_Ciphertext, 32, "%u", sample.a[0]);
	for(int i = 1; i < 500; ++i)
	{
		snprintf(c_Temp, 32, "%u", sample.a[i]);
		strcat(c_Ciphertext, c_Temp);
		c_Temp[0] = '\0';
	}
	snprintf(c_Temp, 32, "%u", sample.b);
	strcat(c_Ciphertext, c_Temp);
	c_Temp[0] = '\0';
	return c_Ciphertext;
}

double evaluate_without_hashing(int gate_index)
{
	long plaintext1,plaintext2;
  	plaintext1 = rand()%2;
  	plaintext2 = rand()%2;
  
  	LWE::Encrypt(&ciphertextA, LWEsk, plaintext1);
  	LWE::Encrypt(&ciphertextB, LWEsk, plaintext2);
  
  	auto start = chrono::high_resolution_clock::now();
  	
  	BinGate gate = static_cast<BinGate>(gate_index);
  	FHEW::HomGate(&Result, gate, EK, ciphertextA, ciphertextB);
  	
  	auto end = chrono::high_resolution_clock::now();
    	
    	chrono::duration<double> diff = end - start;

    	return diff.count();
}

double evaluate_with_hashing(int gate_index)
{
	int plaintext1,plaintext2;
  	plaintext1 = rand()%2;
  	plaintext2 = rand()%2;
  
  	LWE::Encrypt(&ciphertextA, LWEsk, plaintext1);
  	LWE::Encrypt(&ciphertextB, LWEsk, plaintext2);
  	
  	strcpy(c_ciphertextA, concat_cipher(ciphertextA));
    	sha256_hex(c_ciphertextA, strlen(c_ciphertextA), hex_ciphertextA);
    	
    	strcpy(c_ciphertextB, concat_cipher(ciphertextB));
    	sha256_hex(c_ciphertextB, strlen(c_ciphertextB), hex_ciphertextB);
  
  	auto start = chrono::high_resolution_clock::now();
  	
  	BinGate gate = static_cast<BinGate>(gate_index);
  	FHEW::HomGate(&Result, gate, EK, ciphertextA, ciphertextB);
  	
  	strcpy(c_Result, concat_cipher(Result));
  	char *s_Result = concat(c_Result, hex_ciphertextA, hex_ciphertextB);
  	sha256_hex(s_Result, strlen(s_Result), hex_Result);
  	
  	auto end = chrono::high_resolution_clock::now();
    	
    	chrono::duration<double> diff = end - start;

    	return diff.count();
}

int main(int argc, char *argv[]) {

  	srand(967); //srand(967); srand(1073); srand(2512); srand(2406); srand(2022); for testing.

  	cerr << "Setting up FHEW \n";
  	FHEW::Setup();
  	cerr << "Generating secret key ... ";
  
  	LWE::KeyGen(LWEsk);
  
  	FILE *secret_key = fopen("secret_key.txt","a");
  	for(int i = 0; i < n; ++i) {
    		fprintf(secret_key, "%d ", LWEsk[i]);
  	}
  	fprintf(secret_key, "\n");
  	fclose(secret_key);
  
  	cerr << " Done.\n";
  	cerr << "Generating evaluation key ... this may take a while ... ";
  
  	FHEW::KeyGen(&EK, LWEsk);
  	cerr << " Done.\n\n";
  	
    	double time_NAND_wo_hashing = 0.0;
    	
    	for(int i = 1; i <= 10; ++i)
    	{
    		time_NAND_wo_hashing = time_NAND_wo_hashing + evaluate_without_hashing(3);
    	}
    	
    	time_NAND_wo_hashing = time_NAND_wo_hashing / 10.0;

  	cerr << "Time required to run NAND gate without hash generation: " << time_NAND_wo_hashing << "s\n" << endl;
  	
    	double time_NAND_w_hashing = 0.0;
    	
    	for(int i = 1; i <= 10; ++i)
    	{
    		time_NAND_w_hashing = time_NAND_w_hashing + evaluate_with_hashing(3);
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
    		time_NOR_wo_hashing = time_NOR_wo_hashing + evaluate_without_hashing(1);
    	}
    	
    	time_NOR_wo_hashing = time_NOR_wo_hashing / 10.0;

  	cerr << "Time required to run NOR gate without hash generation: " << time_NOR_wo_hashing << "s\n" << endl;
  	
    	double time_NOR_w_hashing = 0.0;
    	
    	for(int i = 1; i <= 10; ++i)
    	{
    		time_NOR_w_hashing = time_NOR_w_hashing + evaluate_with_hashing(1);
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
    		time_OR_wo_hashing = time_OR_wo_hashing + evaluate_without_hashing(1);
    	}
    	
    	time_OR_wo_hashing = time_OR_wo_hashing / 10.0;

  	cerr << "Time required to run OR gate without hash generation: " << time_OR_wo_hashing << "s\n" << endl;
  	
    	double time_OR_w_hashing = 0.0;
    	
    	for(int i = 1; i <= 10; ++i)
    	{
    		time_OR_w_hashing = time_OR_w_hashing + evaluate_with_hashing(0);
    	}
    	
    	time_OR_w_hashing = time_OR_w_hashing / 10.0;

  	cerr << "Time required to run OR gate with hash generation: " << time_OR_w_hashing << "s\n" << endl;
  	
  	double diff_OR_time = time_OR_w_hashing - time_OR_wo_hashing;
  	double diff_OR_percent = round(((diff_OR_time/time_OR_wo_hashing)*100)*10)/10.0;
  	
  	diff_OR_time = diff_OR_time > 0 ? diff_OR_time : -diff_OR_time;
  	diff_OR_percent = diff_OR_percent > 0 ? diff_OR_percent : -diff_OR_percent;
  	
  	cerr << "Overhead introduced due to hashing in OR: " << diff_OR_time << "s or " << diff_OR_percent <<"%\n" << endl;
  	
  	double diff_avg_time = (diff_NAND_time + diff_AND_time + diff_NOR_time + diff_OR_time) / 4.0;
  	double diff_avg_percent = round(((diff_NAND_percent + diff_AND_percent + diff_NOR_percent + diff_OR_percent) / 4.0)*10)/10.0;
  	
  	cerr << "Average increase in runtime due to hashing: " << diff_avg_time << "s or " << diff_avg_percent <<"%\n" << endl;
  	
}


