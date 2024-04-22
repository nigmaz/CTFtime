#include <iostream>
#include <bitset>


unsigned char __ROR1__(unsigned char value, int shift) {
    return ((value >> shift) | (value << (8 - shift))) & 0xFF;
}

unsigned char __ROL1__(unsigned char value, int shift) {
    return ((value << shift) | (value >> (8 - shift))) & 0xFF;
}

int main() {
    unsigned char tmp = 0xD7; 
	std::cout << "Root value: " << std::bitset<8>(tmp) << std::endl << std::endl;
//    int v6 = 0xf3a8d24e;
	int v6 = 9;
	do
      {
        tmp = __ROL1__(tmp, 1);
        --v6;
        std::cout << "Rotated value: " << std::bitset<8>(tmp) << std::endl;
        printf("Rotated char: %c\n", tmp);
      }
      while ( v6 );

	printf("Rotated char: %c\n", tmp);

    return 0;
}


