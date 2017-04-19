/*
 Enco_Crypto.h - Crypto functions for MQTT with EnCo.
  Proximus EnCo
  https://enco.io
*/

#ifndef Enco_Crypto_h
#define Enco_Crypto_h

//#define ENCO_DEBUG

#include <Arduino.h>
#include <time.h>
#include "Crypto.h"
#include "AES.h"
#include "CBC.h"


class Enco_Crypto {
private:
    AES128 aes128;
    uint8_t iv[16];
    uint8_t buffer[16];
#ifdef ENCO_DEBUG
    void hexPrint(const uint8_t* buffer, size_t len);
    void hexPrintByte(const uint8_t value);
#endif
public:
    Enco_Crypto();
    virtual ~Enco_Crypto();

	void clean();

    size_t keySize() const;

    bool setKey(const uint8_t *key, size_t len);
    bool setIV(const uint8_t *iv, size_t len);
    size_t getIV(uint8_t *output, size_t offset);

    size_t encrypt(uint8_t *output, size_t offset, const uint8_t *input, size_t len);
    size_t encryptToken(uint8_t *output, size_t offset, time_t epochTime, const char* pass);

};


#endif
