#ifndef DES_HPP
#define DES_HPP

#include <string>

namespace DES
{
    void des(const std::string& inp, std::string& key, std::string& p_encrypted);
}
#endif
