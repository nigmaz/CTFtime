#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <string.h>
using namespace std;

const char* RC4key = "ZQLODBY4UGXHK5TRYILGMEZZVYU2ILTE";

class RC4{
public:
	RC4(const unsigned char* key, size_t key_length){
		for (int i = 0; i < 256; ++i)
			state_[i] = i;
		
		size_t j = 0;
		for (int i = 0; i < 256; ++i){
			j = (j + state_[i] + key[i % key_length]) % 256;
			swap(state_[i], state_[j]);
		}
		i_ = j_ = 0;
	}
	
	void Crypt(unsigned char* data, size_t length){
		size_t i = i_;
		size_t j = j_;
		
		for (size_t k = 0; k < length; k++){
			i = (i + 1) % 256;
			j = (j + state_[i]) % 256;
			swap(state_[i], state_[j]);
			data[k] ^= state_[(state_[i] + state_[j]) % 256];
		}
		
		i_ = i;
		j_ = j;
	}
private:
	unsigned char state_[256];
	size_t i_;
	size_t j_;			
};

void LoadDecrypt(){
	ifstream file("SUSFLAG101.bin", ios::binary | ios::ate);
	if(!file.is_open()){
		cerr << "Load resource ERROR!!!" << endl; 
		return;
	}
	
	streamsize size = file.tellg();
	file.seekg(0, ios::beg);
	
	vector<char> buffer(size);
	if(!file.read(buffer.data(), size)){
		cerr << "Read resource ERROR!!!" << endl;
		return;
	}
	
	RC4 rc4((const unsigned char*)RC4key, strlen(RC4key));
	rc4.Crypt(reinterpret_cast<unsigned char*>(buffer.data()), size);
	
	ofstream decrypted_file("SusFlag.jpg", ios::binary);
	if (!decrypted_file.is_open()){
		cerr << "Create images file.jpg ERROR!!!" << endl;
		return;
	}
	decrypted_file.write(buffer.data(), size);
	cout << "Extracted file.jpg DONE!!!" << endl;
}

int main(){
	LoadDecrypt();
	return 0;
}




