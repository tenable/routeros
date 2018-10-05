#include "rc4.hpp"
#include <iostream>
RC4::RC4() :
    m_S(),
    m_i(0),
    m_j(0)
{
}

RC4::~RC4() {
}

void RC4::setKey(const std::string& p_key) {
    for(std::size_t i = 0; i < 256; ++i) {
        m_S[i]=i;
    }

    int j = 0;
    for(int i=0;i<256;++i){
        j=(j+p_key[i % p_key.length()] + m_S[i]) & 0xff;
        unsigned char t = m_S[i];
        m_S[i] = m_S[j];
        m_S[j] = t;
    }
    m_i = 0;
    m_j = 0;
    for(int i=0; i < 768; ++i)
        gen();
}

unsigned char RC4::gen() {
    int i=m_i=(m_i+1)&255;
    int j=m_j=(m_j+m_S[i])&255;
    int t=m_S[i];
    m_S[i]=m_S[j];
    m_S[j]=t;
    return m_S[(m_S[i]+m_S[j])&255];
}

std::string RC4::encrypt(const std::string& p_str) {
    std::string a;
    a.resize(p_str.length(), 0);
    for(std::size_t i=0; i < p_str.length(); ++i) {
        a[i] ^= gen();
    }
    return a;
}

std::string RC4::decrypt(const std::string& p_str, int p_off) {
    std::string a;
    a.resize(p_str.length(), 0);
    for(std::size_t i = 0; i < (p_str.length() - p_off); ++i){
        unsigned char generated = gen();
        a[i] = p_str[i+p_off] ^ generated;
    }
    return a;
}
