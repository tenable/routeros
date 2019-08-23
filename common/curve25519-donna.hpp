#ifndef CURVE25519_DONNA_H
#define CURVE25519_DONNA_H

#include <boost/cstdint.hpp>

int curve25519_donna(boost::uint8_t* p_pub_key, const boost::uint8_t* p_priv_key,  const boost::uint8_t* p_basepoint);

#endif
