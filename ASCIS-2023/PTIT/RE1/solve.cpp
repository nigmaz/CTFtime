#include<bits/stdc++.h>
using namespace std;

char Str[] = "LcKUC8JBInrfjVzdeb8qCHE8ozXSMt";
int byte_5BFA20 = 0;

signed int __stdcall TlsCallback_1()
{
  signed int result; // eax
  signed int v4; // [esp+0h] [ebp-2Ch]
  signed int i; // [esp+4h] [ebp-28h]
  char v6[30]; // [esp+8h] [ebp-24h]
//  char v7[2]; // [esp+24h] [ebp-8h] BYREF

  result = byte_5BFA20;
  if ( !byte_5BFA20 )
  {
    v6[0] = 0;
    v6[1] = 13;
    v6[2] = 51;
    v6[3] = 28;
    v6[4] = 16;
    v6[5] = 98;
    v6[6] = 120;
    v6[7] = 13;
    v6[8] = 26;
    v6[9] = 29;
    v6[10] = 36;
    v6[11] = 36;
    v6[12] = 44;
    v6[13] = 34;
    v6[14] = 56;
    v6[15] = 28;
    v6[16] = 92;
    v6[17] = 17;
    v6[18] = 96;
    v6[19] = 62;
    v6[20] = 12;
    v6[21] = 2;
    v6[22] = 36;
    v6[23] = 77;
    v6[24] = 10;
    v6[25] = 11;
    v6[26] = 50;
    v6[27] = 28;
    v6[28] = 59;
    v6[29] = 60;
    // memcpy(v7, ";<", sizeof(v7));
    
    result = strlen(Str);
    v4 = result;
    for ( i = 0; i < v4; ++i )
    {
      result = v6[i] ^ Str[i];
      Str[i] = result;
    }
  }
  return result;
}

// handleFlag2_A91230(a2, 26); a2=5
int __cdecl handleFlag2_A91230(int a1, int a2)
{
  int i; // [esp+0h] [ebp-4h]
  int v4; // [esp+Ch] [ebp+8h]

  v4 = a1 % a2;                                 // 5
  for ( i = 1; i < a2; ++i )
  {
    if ( i * v4 % a2 == 1 )
      return i;
  }
  return -1;
}

// handleFlag1_A91280(Str, 5, 8);
void __cdecl handleFlag1_A91280(char *Str, int a2, int a3)
{
  int v3; // [esp+0h] [ebp-14h]
  signed int Count; // [esp+4h] [ebp-10h]
  char *Block; // [esp+8h] [ebp-Ch]
  signed int i; // [esp+Ch] [ebp-8h]
  char v7; // [esp+13h] [ebp-1h]

  Count = strlen(Str) + 1;
  Block = (char *)calloc(Count, 1u);
  v3 = handleFlag2_A91230(a2, 26);              // v3 = 21
  for ( i = 0; i < Count; ++i )
  {
    v7 = Str[i];
    if ( v7 < 65 || v7 > 90 )                   // upcase
    {
      if ( v7 >= 97 && v7 <= 122 )              // lowcase
        v7 = v3 * ((v7 - 97 - a3 + 26) % 26) % 26 + 97;
    }
    else
    {
      v7 = v3 * ((v7 - 65 - a3 + 26) % 26) % 26 + 65;
    }
    Block[i] = v7;
  }
  printf("\nATTT{<decodeBase58(flag)>} : %s\n", Block);
  free(Block);
}

int main(){
	TlsCallback_1();
	cout << Str << endl;
	handleFlag1_A91280(Str, 5, 8);
	return 0;
}



//0x012E81A8
//
//5, 1
//10, 2
//15, 3
//20, 4
//25, 5
//4, 6
//9, 7
//14, 8
//19, 9
//24, 10
//3, 11
//8, 12
//13, 13
//18, 14
//23, 15
//2, 16
//7, 17
//12, 18
//17, 19
//22, 20
//1, 21 | 0x15
//6, 22
//11, 23
//16, 24
//21, 25
//0, 26

