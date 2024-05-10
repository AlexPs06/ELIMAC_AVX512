#include <iostream>
#include <wmmintrin.h>
#include <immintrin.h>
#include <emmintrin.h>

#define ALIGN(n) __attribute__ ((aligned(n)))
#define pipeline 1

#define EXPAND_ASSIST(v1,v2,v3,v4,shuff_const,aes_const)                    \
    v2 = _mm_aeskeygenassist_si128(v4,aes_const);                           \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 16));        \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 140));       \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v2 = _mm_shuffle_epi32(v2,shuff_const);                                 \
    v1 = _mm_xor_si128(v1,v2)

using namespace std;

void H(__m512i * nonce,  __m512i *key, unsigned rounds,unsigned nblks);
void I(__m512i * nonce,  __m512i  key, unsigned rounds,unsigned nblks);
void ELIMAC(unsigned char *K_1, unsigned char *K_2, unsigned char *M, int size, unsigned char *T);
static inline void AES_encrypt(__m128i tmp, __m128i *out,__m128i *key, unsigned rounds);
int main(){

    ALIGN(64) unsigned char plaintext[64]=  {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                                             0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                                             0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                                             0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 
                                            };
    ALIGN(16) unsigned char tag[16 ]={ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
    ALIGN(16) unsigned char K_1[16 ]={ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
    ALIGN(16) unsigned char K_2[16 ]={ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};

    ELIMAC(K_1, K_2, plaintext, 64, tag);

    return 0;
}


void ELIMAC(unsigned char *K_1, unsigned char *K_2, unsigned char *M, int size, unsigned char *T){

    int m_blocks = 0;
    if (size%64==0)
        m_blocks=size/64;
    else
        m_blocks=(size/64) + 1;

    __m512i * plain_text_512 = (__m512i*) M;
    __m512i nonce;
    __m512i S_temp;
    __m128i Tag;
    __m512i nonce_temp[1];
    __m512i keys_512[11];
    __m128i keys_128[11];
    __m512i keys_0 = _mm512_setzero_si512();
    __m512i sum_nonce= _mm512_set_epi64(0,4, 0,4, 0,4, 0,4);

    nonce = _mm512_set_epi64(0,0, 0,1, 0,2, 0,3);
    union {__m128i bl128[4]; __m512i bl512;} S;
    
    for (size_t i = 0; i < m_blocks; i++){

        nonce=_mm512_add_epi64(nonce, sum_nonce);
        nonce_temp[0]=nonce; 
        
        H(nonce_temp,  keys_512, 6, pipeline);
        
        plain_text_512[i]=_mm512_xor_si512(plain_text_512[i],nonce_temp[0]);

        I(plain_text_512,  keys_0, 4,pipeline);

        S_temp=_mm512_xor_si512(plain_text_512[i],S_temp);

    }
    
    S.bl512=S_temp;
    for (size_t i = 0; i < 4; i++){
        Tag=_mm_xor_si128(Tag,S.bl128[i]);
    }
    AES_encrypt(Tag, &Tag, keys_128, 10);
    
    
	_mm_store_si128 ((__m128i*)T,Tag);

}




void H(__m512i * nonce,  __m512i *key, unsigned rounds,unsigned nblks){
    int i = 0;
    int j = 0;
	const __m512i *sched = ((__m512i *)(key));
    for (i=0; i<nblks; ++i)
	    nonce[i] =_mm512_xor_si512(nonce[i], sched[0]);//4cc
	for(j=1; j<rounds; ++j)
	    for (i=0; i<nblks; ++i)
		    nonce[i] = _mm512_aesenc_epi128(nonce[i], sched[j]); //80cc
    for (i=0; i<nblks; ++i)
	    nonce[i] =_mm512_aesenclast_epi128(nonce[i], sched[j]);
}

void I(__m512i * nonce,  __m512i  key, unsigned rounds,unsigned nblks){
    int i = 0;
    int j = 0;
    for (i=0; i<nblks; ++i)
	    nonce[i] =_mm512_xor_si512(nonce[i], key);//4cc
	for(j=1; j<rounds; ++j)
	    for (i=0; i<nblks; ++i)
		    nonce[i] = _mm512_aesenc_epi128(nonce[i], key); //80cc
    for (i=0; i<nblks; ++i)
	    nonce[i] =_mm512_aesenclast_epi128(nonce[i], key);
}


static inline void AES_encrypt(__m128i tmp, __m128i *out,__m128i *key, unsigned rounds){
	int j;
	tmp = _mm_xor_si128 (tmp,key[0]);
	for (j=1; j<rounds; j++)  tmp = _mm_aesenc_si128 (tmp,key[j]);
	tmp = _mm_aesenclast_si128 (tmp,key[j]);
	_mm_store_si128 ((__m128i*)out,tmp);
}


static void AES_128_Key_Expansion(const unsigned char *userkey, void *key)
{
    __m128i x0,x1,x2;
    __m128i *kp = (__m128i *)key;
    kp[0] = x0 = _mm_loadu_si128((__m128i*)userkey);
    x2 = _mm_setzero_si128();
    EXPAND_ASSIST(x0,x1,x2,x0,255,1);   kp[1]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,2);   kp[2]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,4);   kp[3]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,8);   kp[4]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,16);  kp[5]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,32);  kp[6]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,64);  kp[7]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,128); kp[8]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,27);  kp[9]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,54);  kp[10] = x0;
}

static void AES_cast_128_to_512_key2(__m128 *key,__m512 *key_512){
    union {__m128 oa128[4]; __m512 oa512;} oa;
    for(int i = 0; i< 11; i++ ){
        oa.oa128[0] = key[i];
        oa.oa128[1] = key[i];
        oa.oa128[2] = key[i];
        oa.oa128[3] = key[i];
        key_512[i]=oa.oa512;
    }

}