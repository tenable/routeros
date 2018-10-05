#include <string>
#include <boost/cstdint.hpp>
#include <iostream>

#include "md4.hpp"

namespace MD4
{
    const boost::uint32_t k[3] =
    {
        0,0x5a827999,0x6Ed9Eba1
    };

    const boost::int8_t s[3][4] =
    {
        { 29,25,21,13 },
        { 29,27,23,19 },
        { 29,23,21,17 }
    };

    const boost::int8_t lut[3][16] =
    {
        { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 },
        { 0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15 },
        { 0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15 }
    };

    boost::int32_t rrotate(boost::uint32_t v, boost::uint8_t r){
        return(v>>r)|(v<<(32-r));
    }

    boost::int32_t unpackle(const std::string& a, boost::uint8_t off){
        boost::int32_t v=0;
        for(std::size_t i=0;i<4;++i){
            v|=(a[off+i] & 0xff)<<(i*8);
        }
        return v;
    }

    void packle(std::string& a, std::size_t off, std::size_t v){
        for(std::size_t i=0;i<4;++i){
            a[off+i]=(v>>(i*8))&0xff;
        }
    }

    std::string md4(std::string msg) {
        std::size_t len = msg.length();
        std::size_t totalLen=len+9;
        totalLen=(totalLen+63)&-64;
        std::string padding;
        padding.push_back(0x80);
        for(std::size_t i=len+1;i<totalLen;++i)
            padding.push_back(0);
        msg=msg.append(padding);
        packle(msg,totalLen-8,len*8);
        boost::int32_t h0=0x67452301;
        boost::int32_t h1=0xefcdab89;
        boost::int32_t h2=0x98badcfe;
        boost::int32_t h3=0x10325476;
        boost::int32_t w[16] = { 0 };
        for(std::size_t j=0;j<msg.length();j+=64){
            for(std::size_t i=0;i<16;++i) {
                w[i]=unpackle(msg,j+i*4);
            }
            boost::int32_t a=h0;
            boost::int32_t b=h1;
            boost::int32_t c=h2;
            boost::int32_t d=h3;
            for(boost::int32_t i=0;i<48;++i){
                boost::int32_t r=i>>4;
                boost::int32_t f = 0;
                switch(r){
                    case 0:
                        f=((c^d)&b)^d;
                        break;
                    case 1:
                        f=(b&c)|(b&d)|(c&d);
                        break;
                    case 2:
                        f=b^c^d;
                        break;
                    default:
                        break;
                }
                boost::int32_t t = a;
                t += w[lut[r][i&0xf]];
                t += k[r];
                t += f;
                t=rrotate(t,s[r][i&3]);
                a=d;
                d=c;
                c=b;
                b=t;
            }
            h0=(h0+a);
            h1=(h1+b);
            h2=(h2+c);
            h3=(h3+d);
        }
        std::string res;
        res.resize(16,0);
        packle(res,0,h0);
        packle(res,4,h1);
        packle(res,8,h2);
        packle(res,12,h3);
        return res;
    }
}
