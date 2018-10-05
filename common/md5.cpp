#include <cstdio>
#include <cstring>
#include "md5.hpp"


/*
    * MD5 transform constants.
    * reference: RFC 1321 3.4
    */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

/*
* MD5 transform auxiliary functions, optimized for architectures
* without AND-NOT instruction.
* reference: RFC 1321 3.4
*/
#define F(x, y, z) (z ^ (x & (y ^ z)))
#define G(x, y, z) (y ^ (z & (x ^ y)))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | ~z))

#define STEP(f, a, b, c, d, x, t, s)                \
a += f(b, c, d) + x + t;                            \
a = ((a << s) | ((a & 0xffffffff) >> (32 - s)));    \
a += b;

MD5::MD5() :
    buffer(),
    digest(),
    state(),
    lo(),
    hi(),
    finalized(false)
{
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;
}

MD5::~MD5()
{
}

/*
* Cut the concatenated data into chuncks of BLOCK_SIZE,
* then transform them into the hash.
* reference: RFC 1321
*/
MD5& MD5::update(const unsigned char* input, std::size_t inputLen)
{
    // compute number of bytes mod 64
    std::size_t index = (uint32_t)((lo >> 3) & 0x3F);

    // update the message length
    if ((lo += ((boost::uint32_t)inputLen << 3)) < ((boost::uint32_t)inputLen << 3))
        hi++;
    hi += ((boost::uint32_t)inputLen >> 29);

    std::size_t partLen = 64 - index;

    // update the states using the new message
    std::size_t i;
    if (inputLen >= partLen)
    {
        memcpy(&buffer[index], input, partLen);
        transform(buffer);

        for (i = partLen; i + 64 <= inputLen; i += 64)
        {
            transform(&input[i]);
        }

        index = 0;
    }
    else
    {
        i = 0;
    }

    // buffer the remainder
    memcpy(&buffer[index], &input[i], inputLen - i);
    return *this;
}

/*
* Signed char interface of update.
*/
MD5& MD5::update(const char* input, std::size_t inputLen)
{
    return update((const boost::uint8_t*)input, inputLen);
}

/*
* Append padding bits and length, then wrap it up.
* reference: RFC 1321 3.2, 3.3
*/
MD5& MD5::finalize()
{
    static boost::uint8_t PADDING[64] = {0};
    PADDING[0] = 0x80;

    if (!finalized)
    {
        // save the length
        boost::uint8_t bits[8];
        memcpy(bits, &lo, 4);
        memcpy(bits + 4, &hi, 4);

        // pad the 1 bit and zeroes
        std::size_t index = (boost::uint32_t)((lo >> 3) & 0x3f);
        std::size_t padLen = (index < 56) ? (56 - index) : (120 - index);
        update(PADDING, padLen);

        // append length
        update(bits, 8);

        // store the state
        memcpy(digest, state, 16);

        // wipe out sensitive data
        memset(buffer, 0, sizeof buffer);
        hi = lo = 0;

        finalized = true;
    }

    return *this;
}

/*
 * Output the digest as a string,
 * 4 * 4-byte word * 2 characters per word = 32 characters.
 * reference: RFC 1321 3.5
 */
std::string MD5::getDigest() const
{
    if (!finalized)
    {
        return std::string();
    }

    std::string ret_val(reinterpret_cast<const char*>(&digest[0]), 16);
    return ret_val;
}

/*
* Output the digest as a string,
* 4 * 4-byte word * 2 characters per word = 32 characters.
* reference: RFC 1321 3.5
*/
std::string MD5::toString() const
{
    if (!finalized)
    {
        return std::string();
    }

    char result[33] = {0};

    for (int i = 0; i < 16; ++i)
    {
        sprintf(result + i * 2, "%02x", digest[i]);
    }

    return std::string(result);
}

/*
* The core of the MD5 algorithm, updating the existing MD5 hash to
* reflect the addition of new data. update() will cut the data
* into blocks for it.
* reference: RFC 1321 3.4
*/
void MD5::transform(const boost::uint8_t block[64])
{
    boost::uint32_t a = state[0],
    b = state[1],
    c = state[2],
    d = state[3],
    x[16] = { 0 };

    memcpy(x, block, 64);

    /* Round 1 */
    STEP(F, a, b, c, d, x[ 0], 0xd76aa478, S11); /* 1 */
    STEP(F, d, a, b, c, x[ 1], 0xe8c7b756, S12); /* 2 */
    STEP(F, c, d, a, b, x[ 2], 0x242070db, S13); /* 3 */
    STEP(F, b, c, d, a, x[ 3], 0xc1bdceee, S14); /* 4 */
    STEP(F, a, b, c, d, x[ 4], 0xf57c0faf, S11); /* 5 */
    STEP(F, d, a, b, c, x[ 5], 0x4787c62a, S12); /* 6 */
    STEP(F, c, d, a, b, x[ 6], 0xa8304613, S13); /* 7 */
    STEP(F, b, c, d, a, x[ 7], 0xfd469501, S14); /* 8 */
    STEP(F, a, b, c, d, x[ 8], 0x698098d8, S11); /* 9 */
    STEP(F, d, a, b, c, x[ 9], 0x8b44f7af, S12); /* 10 */
    STEP(F, c, d, a, b, x[10], 0xffff5bb1, S13); /* 11 */
    STEP(F, b, c, d, a, x[11], 0x895cd7be, S14); /* 12 */
    STEP(F, a, b, c, d, x[12], 0x6b901122, S11); /* 13 */
    STEP(F, d, a, b, c, x[13], 0xfd987193, S12); /* 14 */
    STEP(F, c, d, a, b, x[14], 0xa679438e, S13); /* 15 */
    STEP(F, b, c, d, a, x[15], 0x49b40821, S14); /* 16 */

    /* Round 2 */
    STEP(G, a, b, c, d, x[ 1], 0xf61e2562, S21); /* 17 */
    STEP(G, d, a, b, c, x[ 6], 0xc040b340, S22); /* 18 */
    STEP(G, c, d, a, b, x[11], 0x265e5a51, S23); /* 19 */
    STEP(G, b, c, d, a, x[ 0], 0xe9b6c7aa, S24); /* 20 */
    STEP(G, a, b, c, d, x[ 5], 0xd62f105d, S21); /* 21 */
    STEP(G, d, a, b, c, x[10],  0x2441453, S22); /* 22 */
    STEP(G, c, d, a, b, x[15], 0xd8a1e681, S23); /* 23 */
    STEP(G, b, c, d, a, x[ 4], 0xe7d3fbc8, S24); /* 24 */
    STEP(G, a, b, c, d, x[ 9], 0x21e1cde6, S21); /* 25 */
    STEP(G, d, a, b, c, x[14], 0xc33707d6, S22); /* 26 */
    STEP(G, c, d, a, b, x[ 3], 0xf4d50d87, S23); /* 27 */
    STEP(G, b, c, d, a, x[ 8], 0x455a14ed, S24); /* 28 */
    STEP(G, a, b, c, d, x[13], 0xa9e3e905, S21); /* 29 */
    STEP(G, d, a, b, c, x[ 2], 0xfcefa3f8, S22); /* 30 */
    STEP(G, c, d, a, b, x[ 7], 0x676f02d9, S23); /* 31 */
    STEP(G, b, c, d, a, x[12], 0x8d2a4c8a, S24); /* 32 */

    /* Round 3 */
    STEP(H, a, b, c, d, x[ 5], 0xfffa3942, S31); /* 33 */
    STEP(H, d, a, b, c, x[ 8], 0x8771f681, S32); /* 34 */
    STEP(H, c, d, a, b, x[11], 0x6d9d6122, S33); /* 35 */
    STEP(H, b, c, d, a, x[14], 0xfde5380c, S34); /* 36 */
    STEP(H, a, b, c, d, x[ 1], 0xa4beea44, S31); /* 37 */
    STEP(H, d, a, b, c, x[ 4], 0x4bdecfa9, S32); /* 38 */
    STEP(H, c, d, a, b, x[ 7], 0xf6bb4b60, S33); /* 39 */
    STEP(H, b, c, d, a, x[10], 0xbebfbc70, S34); /* 40 */
    STEP(H, a, b, c, d, x[13], 0x289b7ec6, S31); /* 41 */
    STEP(H, d, a, b, c, x[ 0], 0xeaa127fa, S32); /* 42 */
    STEP(H, c, d, a, b, x[ 3], 0xd4ef3085, S33); /* 43 */
    STEP(H, b, c, d, a, x[ 6],  0x4881d05, S34); /* 44 */
    STEP(H, a, b, c, d, x[ 9], 0xd9d4d039, S31); /* 45 */
    STEP(H, d, a, b, c, x[12], 0xe6db99e5, S32); /* 46 */
    STEP(H, c, d, a, b, x[15], 0x1fa27cf8, S33); /* 47 */
    STEP(H, b, c, d, a, x[ 2], 0xc4ac5665, S34); /* 48 */

    /* Round 4 */
    STEP(I, a, b, c, d, x[ 0], 0xf4292244, S41); /* 49 */
    STEP(I, d, a, b, c, x[ 7], 0x432aff97, S42); /* 50 */
    STEP(I, c, d, a, b, x[14], 0xab9423a7, S43); /* 51 */
    STEP(I, b, c, d, a, x[ 5], 0xfc93a039, S44); /* 52 */
    STEP(I, a, b, c, d, x[12], 0x655b59c3, S41); /* 53 */
    STEP(I, d, a, b, c, x[ 3], 0x8f0ccc92, S42); /* 54 */
    STEP(I, c, d, a, b, x[10], 0xffeff47d, S43); /* 55 */
    STEP(I, b, c, d, a, x[ 1], 0x85845dd1, S44); /* 56 */
    STEP(I, a, b, c, d, x[ 8], 0x6fa87e4f, S41); /* 57 */
    STEP(I, d, a, b, c, x[15], 0xfe2ce6e0, S42); /* 58 */
    STEP(I, c, d, a, b, x[ 6], 0xa3014314, S43); /* 59 */
    STEP(I, b, c, d, a, x[13], 0x4e0811a1, S44); /* 60 */
    STEP(I, a, b, c, d, x[ 4], 0xf7537e82, S41); /* 61 */
    STEP(I, d, a, b, c, x[11], 0xbd3af235, S42); /* 62 */
    STEP(I, c, d, a, b, x[ 2], 0x2ad7d2bb, S43); /* 63 */
    STEP(I, b, c, d, a, x[ 9], 0xeb86d391, S44); /* 64 */

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    // wipe out sensitive data
    memset(x, 0, sizeof x);
}
