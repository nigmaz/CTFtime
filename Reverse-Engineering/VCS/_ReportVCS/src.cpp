#include <iostream>
using namespace std;



unsigned char* RC4(unsigned char * plaintext, unsigned char * ciphertext, unsigned char * key, unsigned int keyL, unsigned int messageL){
	int i;
	unsigned char s[256];
	unsigned char* keystream;
	KSA(s, key, keyL);
	keystream = PRGA(s, messageL);
	
	for ( i = 0; i < messageL; i++){
		ciphertext[i] = plaintext[i] ^ keystream[i];
	}
	return ciphertext;
}

int main(){
	unsigned char aN[] = 
	{
		241, 6, 180, 254, 70, 231, 220, 160, 113, 103, 
		145, 43, 72, 230, 135, 149, 58, 45, 163, 15,
		140, 193, 68, 176, 134, 200, 31, 105, 9, 197,
		144, 134, 51, 59, 143, 163, 154, 94, 66, 143, 
		25, 0, 0, 0
	}
	
	unsigned char * plaintext = (unsigned char *)aN;
	unsigned char * key = (unsigned char *)"BROKENVM";
	unsigned char * ciphertext = (unsigned char *)malloc(sizeof(unsigned char) * strlen((const char *)plaintext));
	RC4(plaintext, ciphertext, key, s, strlen((const char*)key), strlen((const char*)plaintext));
	cout << ciphertext << endl;
	return 0;
}

