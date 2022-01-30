/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
--------------------------------
CudaDucoMiner by Khaluza Yaroslav
*/

/* #define LITTLE_ENDIAN * This should be #define'd already, if true. */
/* #define SHA1HANDSOFF * Copies data before messing with it. */
#define SHA1HANDSOFF
#include <stdio.h>
#include <string.h>
/* for uint32_t */
#include <stdint.h>
typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;
#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))
#if BYTE_ORDER == LITTLE_ENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#elif BYTE_ORDER == BIG_ENDIAN
#define blk0(i) block->l[i]
#else
#error "Endianness not defined!"
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);
__device__ void SHA1Transform(uint32_t state[5], const unsigned char buffer[64])
{
    uint32_t a, b, c, d, e;

    typedef union
    {
        unsigned char c[64];
        uint32_t l[16];
    } CHAR64LONG16;

#ifdef SHA1HANDSOFF
    CHAR64LONG16 block[1];      /* use array to appear as a pointer */

    memcpy(block, buffer, 64);
#else
    /* The following had better never be used because it causes the
     * pointer-to-const buffer to be cast into a pointer to non-const.
     * And the result is written through.  I threw a "const" in, hoping
     * this will cause a diagnostic.
     */
    CHAR64LONG16* block = (const CHAR64LONG16*)buffer;
#endif
    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a, b, c, d, e, 0);
    R0(e, a, b, c, d, 1);
    R0(d, e, a, b, c, 2);
    R0(c, d, e, a, b, 3);
    R0(b, c, d, e, a, 4);
    R0(a, b, c, d, e, 5);
    R0(e, a, b, c, d, 6);
    R0(d, e, a, b, c, 7);
    R0(c, d, e, a, b, 8);
    R0(b, c, d, e, a, 9);
    R0(a, b, c, d, e, 10);
    R0(e, a, b, c, d, 11);
    R0(d, e, a, b, c, 12);
    R0(c, d, e, a, b, 13);
    R0(b, c, d, e, a, 14);
    R0(a, b, c, d, e, 15);
    R1(e, a, b, c, d, 16);
    R1(d, e, a, b, c, 17);
    R1(c, d, e, a, b, 18);
    R1(b, c, d, e, a, 19);
    R2(a, b, c, d, e, 20);
    R2(e, a, b, c, d, 21);
    R2(d, e, a, b, c, 22);
    R2(c, d, e, a, b, 23);
    R2(b, c, d, e, a, 24);
    R2(a, b, c, d, e, 25);
    R2(e, a, b, c, d, 26);
    R2(d, e, a, b, c, 27);
    R2(c, d, e, a, b, 28);
    R2(b, c, d, e, a, 29);
    R2(a, b, c, d, e, 30);
    R2(e, a, b, c, d, 31);
    R2(d, e, a, b, c, 32);
    R2(c, d, e, a, b, 33);
    R2(b, c, d, e, a, 34);
    R2(a, b, c, d, e, 35);
    R2(e, a, b, c, d, 36);
    R2(d, e, a, b, c, 37);
    R2(c, d, e, a, b, 38);
    R2(b, c, d, e, a, 39);
    R3(a, b, c, d, e, 40);
    R3(e, a, b, c, d, 41);
    R3(d, e, a, b, c, 42);
    R3(c, d, e, a, b, 43);
    R3(b, c, d, e, a, 44);
    R3(a, b, c, d, e, 45);
    R3(e, a, b, c, d, 46);
    R3(d, e, a, b, c, 47);
    R3(c, d, e, a, b, 48);
    R3(b, c, d, e, a, 49);
    R3(a, b, c, d, e, 50);
    R3(e, a, b, c, d, 51);
    R3(d, e, a, b, c, 52);
    R3(c, d, e, a, b, 53);
    R3(b, c, d, e, a, 54);
    R3(a, b, c, d, e, 55);
    R3(e, a, b, c, d, 56);
    R3(d, e, a, b, c, 57);
    R3(c, d, e, a, b, 58);
    R3(b, c, d, e, a, 59);
    R4(a, b, c, d, e, 60);
    R4(e, a, b, c, d, 61);
    R4(d, e, a, b, c, 62);
    R4(c, d, e, a, b, 63);
    R4(b, c, d, e, a, 64);
    R4(a, b, c, d, e, 65);
    R4(e, a, b, c, d, 66);
    R4(d, e, a, b, c, 67);
    R4(c, d, e, a, b, 68);
    R4(b, c, d, e, a, 69);
    R4(a, b, c, d, e, 70);
    R4(e, a, b, c, d, 71);
    R4(d, e, a, b, c, 72);
    R4(c, d, e, a, b, 73);
    R4(b, c, d, e, a, 74);
    R4(a, b, c, d, e, 75);
    R4(e, a, b, c, d, 76);
    R4(d, e, a, b, c, 77);
    R4(c, d, e, a, b, 78);
    R4(b, c, d, e, a, 79);
    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    /* Wipe variables */
    a = b = c = d = e = 0;
#ifdef SHA1HANDSOFF
    memset(block, '\0', sizeof(block));
#endif
}
__device__ void SHA1Init(SHA1_CTX* context) {
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}
__device__ void SHA1Update(SHA1_CTX* context, const unsigned char* data, uint32_t len) {
    uint32_t i;
    uint32_t j;
    j = context->count[0];
    if ((context->count[0] += len << 3) < j)
        context->count[1]++;
    context->count[1] += (len >> 29);
    j = (j >> 3) & 63;
    if ((j + len) > 63)
    {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        SHA1Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64)
        {
            SHA1Transform(context->state, &data[i]);
        }
        j = 0;
    }
    else
        i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}
__device__ void SHA1Final(unsigned char digest[20], SHA1_CTX* context)
{
    unsigned i;

    unsigned char finalcount[8];

    unsigned char c;

#if 0    /* untested "improvement" by DHR */
    /* Convert context->count to a sequence of bytes
     * in finalcount.  Second element first, but
     * big-endian order within element.
     * But we do it all backwards.
     */
    unsigned char* fcp = &finalcount[8];

    for (i = 0; i < 2; i++)
    {
        uint32_t t = context->count[i];

        int j;

        for (j = 0; j < 4; t >>= 8, j++)
            *--fcp = (unsigned char)t
    }
#else
    for (i = 0; i < 8; i++)
    {
        finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);      /* Endian independent */
    }
#endif
    c = 0200;
    SHA1Update(context, &c, 1);
    while ((context->count[0] & 504) != 448)
    {
        c = 0000;
        SHA1Update(context, &c, 1);
    }
    SHA1Update(context, finalcount, 8); /* Should cause a SHA1Transform() */
    for (i = 0; i < 20; i++)
    {
        digest[i] = (unsigned char)
            ((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
    /* Wipe variables */
    memset(context, '\0', sizeof(*context));
    memset(&finalcount, '\0', sizeof(finalcount));
}
__device__ void SHA1(char* hash_out, const char* str, int len) {
    SHA1_CTX ctx;
    unsigned int ii;

    SHA1Init(&ctx);
    for (ii = 0; ii < len; ii += 1) {
        SHA1Update(&ctx, (const unsigned char*)str + ii, 1);
    }
    SHA1Final((unsigned char*)hash_out, &ctx);
}
__device__ __host__ int strlenght(const char* str) {
    short i = 0;
    while (str[i] != '\0') {
        i++;
    }
    return i;
}
__device__ void toHex(char* to, unsigned num) {
    char alphabet[] = "0123456789abcdef";
    to[0] = alphabet[num / 16];
    to[1] = alphabet[num % 16];
    return;
}
__device__ void reverse(char *s, int length)
{
    int c;
    char* begin, * end, temp;

    //length = string_length(s);
    begin = s;
    end = s;

    for (c = 0; c < length - 1; c++)
        end++;

    for (c = 0; c < length / 2; c++)
    {
        temp = *end;
        *end = *begin;
        *begin = temp;

        begin++;
        end--;
    }
}

__device__ char* itoa(int num, char* str, int base = 10)
{
    int i = 0;
    bool isNegative = false;
    if (num == 0)
    {   str[i++] = '0';
        str[i] = '\0';
        return str;}
    if (num < 0 && base == 10){
        isNegative = true;
        num = -num;}

    while (num != 0){
        int rem = num % base;
        str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
        num = num / base;
    }
    if (isNegative)
        str[i++] = '-';
    str[i] = '\0'; // Append string terminator
    reverse(str, i);
    return str;
}

__device__ char* my_strcat(char* destination, const char* source){
    char* ptr = destination + strlenght(destination);
    while (*source != '\0') {
        *ptr++ = *source++;
    }
    *ptr = '\0';
    return destination;}

__device__ void stradd(char* to, int number) {
    const int lenght_str = strlenght(to);
    char tmp[100];
    itoa(number, tmp);
    my_strcat(to, tmp);
}

__device__ int strcomp(const char* X, const char* Y)
{
    while (*X)
    {
        if (*X != *Y) break;
        X++;
        Y++;
    }
    return *(const unsigned char*)X - *(const unsigned char*)Y;
}

#include <iostream>
using namespace std;

__global__ void kernel(char* victim, char* perfect, int span, int* answer) {
    if (*answer != 0) return;
    int tid = threadIdx.x;
    int bid = blockIdx.x;
    char result[21];
    char tmp[41];
    char tmp_victim[200];
    char tmp_perfect[200];

    for (int i = 0; i < 200; i++) {
        tmp_victim[i] = victim[i];
        tmp_perfect[i] = perfect[i];
    }
    int backss = strlenght(tmp_victim);

    int block_size = span / 30;
    int block_start = ((span / 30) * bid);
    int start_i = block_start + (block_size / 1024) * tid;
    int end_i = start_i + (block_size / 1024)+1;

    //for (int i = (span/1024)*tid; i < (span/1024)*tid + (span / 1024)+1; i++) {
    for( int i = start_i; i< end_i; i++){
        
        stradd(tmp_victim, i);
        SHA1(result, tmp_victim, strlenght(tmp_victim));
        for (int offset = 0; offset < 20; offset++) {
            toHex(tmp + (2 * offset), (unsigned)result[offset] & 0xff);
        }
        tmp[40] = '\0';
        if (strcomp(tmp, tmp_perfect) == 0) {*answer = i; break;}
        else tmp_victim[backss] = '\0';
    }
}

#include <sstream>

int main(int argc, char* argv[]){
    //char victim[500];
    //char perfect[500];
    int span, *dev_answer, answer;
    //cin >> victim >> perfect >> span;
    if (argc < 2) {
        cout << "ERROR: so small count of elements ):";
    }

    char* victim = argv[1];
    char* perfect = argv[2];
    stringstream convert(argv[3]); 

    if (!(convert >> span)) {
        cout << "ERROR!!!";
        return;
    }
        

    span = span * 100 + 1;

    char* dev_victim, * dev_perfect;
    cudaMalloc((void**)&dev_victim, sizeof(char) * 200);
    cudaMalloc((void**)&dev_perfect, sizeof(char) * 200);
    cudaMalloc((void**)&dev_answer, sizeof(int));

    cudaMemcpy(dev_victim, victim, sizeof(char) * 200, cudaMemcpyHostToDevice);
    cudaMemcpy(dev_perfect, perfect, sizeof(char) * 200, cudaMemcpyHostToDevice);

    kernel << <1000, 1024 >> > (dev_victim, dev_perfect, span, dev_answer);
    
    cudaMemcpy(&answer, dev_answer, sizeof(int), cudaMemcpyDeviceToHost);

    cout << answer;

}