/*
 Enco_Crypto.cpp - Crypto functions for MQTT with EnCo.
  Proximus EnCo
  https://enco.io
*/

#include "Enco_Crypto.h"
#include "Arduino.h"

Enco_Crypto::Enco_Crypto() {
	clean();
}

Enco_Crypto::~Enco_Crypto() {
	clean();
	aes128.clear();
}

void Enco_Crypto::clean() {
	memset(iv, 0, sizeof(iv));
	memset(buffer, 0, sizeof(buffer));
}

size_t Enco_Crypto::keySize() const {
	return aes128.keySize();
}

bool Enco_Crypto::setKey(const uint8_t *key, size_t len) {
	clean();
    return aes128.setKey(key, len);
}

bool Enco_Crypto::setIV(const uint8_t *iv, size_t len) {
    if (len != 16)
        return false;
    memcpy(this->iv, iv, 16);
    return true;
}

size_t Enco_Crypto::getIV(uint8_t *output, size_t offset) {
	if (offset > 0)
	    output += offset;
    memcpy(output, iv, sizeof(iv));
	return (offset + sizeof(iv));
}

size_t Enco_Crypto::encrypt(uint8_t *output, size_t offset, const uint8_t *input, size_t len) {
#ifdef ENCO_DEBUG
	Serial.print("encrypt: ");
	hexPrint(input, len);
	Serial.print("     iv: ");
	hexPrint(iv, 16);
#endif
    uint8_t posn;
	if (offset > 0)
	    output += offset;
    while (len >= 16) {
        for (posn = 0; posn < 16; ++posn)
            iv[posn] ^= *input++;
        aes128.encryptBlock(iv, iv);
        for (posn = 0; posn < 16; ++posn, ++offset)
            *output++ = iv[posn];
        len -= 16;
    }
	// Send remaining with pkcs5padding padding
	if (len > 0) {
		uint8_t padVal = 16;
        for (posn = 0; posn < len; ++posn, --padVal)
            iv[posn] ^= *input++;
        for ( ; posn < 16; ++posn)
            iv[posn] ^= padVal;
        aes128.encryptBlock(iv, iv);
        for (posn = 0; posn < 16; ++posn, ++offset)
            *output++ = iv[posn];
	}
	return offset;
}

size_t Enco_Crypto::encryptToken(uint8_t *output, size_t offset, time_t epochTime, const char* pass) {
	uint8_t len = 4;
	memcpy(buffer, &epochTime, len);
	while (*pass != 0) {
		buffer[len++] = *pass++;
		if (len >= 16) {
			offset = encrypt(output, offset, buffer, len);
			len = 0;
		}
	}
	if (len > 0) {
		offset = encrypt(output, offset, buffer, len);
	}
	return offset;
}

#ifdef ENCO_DEBUG
void Enco_Crypto::hexPrint(const uint8_t* buffer, size_t len)
{
    Serial.print("0x");
    hexPrintByte(buffer[0]);
    for (int i = 1 ; i < len ; i++ ) {
      Serial.print(", 0x");
      hexPrintByte(buffer[i]);
    }
    Serial.println();
}

void Enco_Crypto::hexPrintByte(const uint8_t value)
{
  if (value < 16) {
    Serial.print('0');
  }
  Serial.print(value,HEX);
}
#endif
