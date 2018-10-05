#include <string>
#include <boost/cstdint.hpp>

namespace DES
{
    unsigned char PC1[2][28] =
    {
        {
            3,11,19,27,4,12,20,28,
            36,44,52,60,5,13,21,29,
            37,45,53,61,6,14,22,30,
            38,46,54,62
        },
        {
            35,43,51,59,2,10,18,26,
            34,42,50,58,1,9,17,25,
            33,41,49,57,0,8,16,24,
            32,40,48,56
        }
    };

    unsigned char PC2[2][24] =
    {
        {
            13,16,10,23,0,4,2,27,
            14,5,20,9,22,18,11,3,
            25,7,15,6,26,19,12,1
        },
        {
            12,23,2,8,18,26,1,11,
            22,16,4,19,15,20,10,27,
            5,24,17,13,21,7,0,3
        }
    };

    unsigned char IP[2][32] =
    {
        {
            57,49,41,33,25,17,9,1,
            59,51,43,35,27,19,11,3,
            61,53,45,37,29,21,13,5,
            63,55,47,39,31,23,15,7
        },
        {
            56,48,40,32,24,16,8,0,
            58,50,42,34,26,18,10,2,
            60,52,44,36,28,20,12,4,
            62,54,46,38,30,22,14,6
        }
    };

    unsigned char P[] = 
    {
        16,25,12,11,3,20,4,15,
        31,17,9,6,27,14,1,22,
        30,24,8,18,0,5,29,23,
        13,19,2,26,10,21,28,7
    };

    boost::uint32_t S[8][8] =
    {
        {
            0x84d8f21d,0x417b3fa6,0xbe6359ca,0x279ce005,
            0x71e41b27,0xd28eac49,0x0d9ac6f0,0xb865533f
        },
        {
            0x7eb20bd4,0xad18904f,0xc7593ce3,0x6186fa25,
            0x8ddbb461,0x7ea7431c,0xf8065f9a,0xc23925e0
        },
        {
            0x2f4af1ac,0x5896c279,0xe4d31d60,0x8b35b70e,
            0xc52f3e49,0xa3fc5892,0x7a14e0b7,0xd68b0d61
        },
        {
            0xc124bce2,0x16db7a47,0xaff30558,0x698e903d,
            0x7bc182b4,0xd827ed1a,0x950cf96f,0x3e5043a6
        },
        {
            0x53be8dd7,0x3a09f660,0xc5287241,0x9fe4ac1b,
            0x6009f63a,0x8dd71bac,0xbe53419f,0xe42872c5
        },
        {
            0x9e0970da,0xa56f4336,0xe75c8d21,0x18f2b4cb,
            0x09d4a61d,0x70839f68,0x3ce2f14b,0xc72e5ab5
        },
        {
            0x7e48d13f,0xe4832bf6,0xad1207c9,0x5ab5906c,
            0x1ba78ed0,0x214df43a,0xc67c68b5,0x9fe25309
        },
        {
            0x417df40e,0x18db2fe2,0xbcc66aa3,0x87305995,
            0x288ec1f4,0x7b12964d,0xe739bc5f,0xd0650aa3
        }
    };

    boost::uint8_t FP[2][32] =
    {
        {
            39,7,47,15,55,23,63,31,
            38,6,46,14,54,22,62,30,
            37,5,45,13,53,21,61,29,
            36,4,44,12,52,20,60,28
        },
        {
            35,3,43,11,51,19,59,27,
            34,2,42,10,50,18,58,26,
            33,1,41,9,49,17,57,25,
            32,0,40,8,48,16,56,24
        }
    };

    boost::uint32_t rrotate(boost::uint32_t v, boost::uint32_t r){
        return(v>>r)|(v<<(32-r));
    }

    void packbe(char* a, std::size_t off, boost::uint32_t v){
        for(std::size_t i=0;i<4;++i){
            a[off+i]=(v>>(24-i*8))&0xff;
        }
    }

    boost::uint32_t permute(boost::uint32_t v, std::size_t count, unsigned char* p){
        boost::uint32_t r=0;
        for(std::size_t i=0; i < count; ++i) {
            r=(r<<1)|((v>>p[i])&1);
        }
        return r;
    }

    boost::uint32_t bpermute(const char* v, std::size_t count, unsigned char* p){
        boost::uint32_t r=0;
        for(boost::uint32_t i=0;i<count;++i){
            r=(r<<1)|((v[p[i]>>3]>>(7-(p[i]&7)))&1);
        }
        return r;
    }

    boost::uint32_t rrotate28(boost::uint32_t v, boost::uint32_t r){
        return((v>>r)|(v<<(28-r)))&0x0fffffff;
    }

    void des(const std::string& inp, std::string& key, std::string& p_encrypted) {
        boost::uint32_t c = bpermute(key.data(), 28, PC1[0]);
        boost::uint32_t d = bpermute(key.data(), 28, PC1[1]);
        boost::uint32_t l = rrotate(bpermute(inp.data(), 32, IP[0]),31);
        boost::uint32_t r = rrotate(bpermute(inp.data(), 32, IP[1]),31);

        boost::uint32_t rot=1;
        for(boost::uint32_t i=0;i<16;++i){
            boost::uint32_t k[2]=
            {
                permute(rrotate28(c,rot),24,PC2[1]),
                permute(rrotate28(d,rot),24,PC2[0])
            };

            for(boost::uint32_t j=0; j<8; ++j){
                boost::uint32_t x=k[j>>2]>>(j&3)*6;
                boost::uint32_t b=(rrotate(r,j*4)^x)&0x3f;
                boost::uint32_t s=(S[j][b>>3]>>((b&7)*4))&0xf;
                l^=rrotate(permute(s<<j*4,32,P),31);
            }
            boost::uint32_t t=l;
            l=r;
            r=t;
            ++rot;
            if(i!=0 && i!=7 && i!=14)
                ++rot;
        }
        char v[8]={};
        packbe(v,0,rrotate(r,1));
        packbe(v,4,rrotate(l,1));
        l=bpermute(v,32,FP[0]);
        r=bpermute(v,32,FP[1]);
        char out[8]={};
        packbe(out,0,l);
        packbe(out,4,r);
        p_encrypted.assign(out, 8);
    }

}