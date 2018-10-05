#ifndef RC4_HPP
#define RC4_HPP

#include <string>

class RC4 {
public:

    RC4();
    ~RC4();

    void setKey(const std::string& p_key);
    unsigned char gen();
    std::string encrypt(const std::string& p_str);
    std::string decrypt(const std::string& p_str, int p_off);

private:
    unsigned char m_S[256];
    unsigned int m_i;
    unsigned int m_j;
};

#endif
