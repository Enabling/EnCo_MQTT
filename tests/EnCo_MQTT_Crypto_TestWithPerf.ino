
/*
This example runs tests on the AES implementation to verify correct behaviour.
*/

#include <string.h>
#include "time.h"

#include "Enco_MQTT_Crypto.h"

struct TestVector
{
    const char *name;
    uint8_t key[16];
    uint8_t initvector[16];
    uint8_t plaintext[16];
    uint8_t ciphertext[16];
};

struct TestVector32
{
    const char *name;
    byte key[16];
    byte initvector[16];
    byte plaintext[32];
    byte ciphertext[32];
};

// Define the ECB test vectors from the FIPS specification.
static TestVector const testVectorNoIV = {
    .name        = "EnCo-NoIV-pad4",
    .key         = {0x9E, 0xDA, 0x13, 0xCA, 0x7D, 0xC2, 0xCD, 0x90,
                    0x01, 0x38, 0x21, 0x67, 0x87, 0x8B, 0x98, 0x29},
    .initvector  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    .plaintext   = {0x58, 0xAA, 0x9D, 0x8E, 0x70, 0x61, 0x73, 0x73,
                    0x77, 0x6F, 0x72, 0x64, 0x04, 0x04, 0x04, 0x04},
    .ciphertext  = {0x5E, 0x3E, 0x7B, 0xD5, 0xF2, 0x25, 0x7D, 0x7F,
                    0xBB, 0xBE, 0x0F, 0xD9, 0xB0, 0xA5, 0x00, 0x80}
};

static TestVector const testVectorWithIV = {
    .name        = "EnCo-IV-pad1",
    .key         = {0x6C, 0x68, 0xE6, 0xD2, 0xA3, 0xC2, 0x52, 0x40,
                    0x90, 0xAF, 0xAF, 0x75, 0xC3, 0xC8, 0x5D, 0x7C},
    .initvector  = {0xDD, 0x40, 0x7D, 0xED, 0x26, 0xF3, 0x8C, 0xD2,
                    0x66, 0xFD, 0x58, 0x14, 0xF2, 0xAD, 0xB2, 0x27},
    .plaintext   = {0x58, 0xAA, 0xAB, 0xBD, 0x70, 0x61, 0x73, 0x73,
                    0x77, 0x6F, 0x72, 0x64, 0x52, 0x65, 0x70, 0x01},
    .ciphertext  = {0x35, 0xFB, 0x5F, 0xAD, 0xD3, 0xF5, 0x13, 0xF5,
                    0x73, 0x47, 0xD5, 0x6F, 0x5A, 0x50, 0x7A, 0x1A}
};

static TestVector32 const testLongVector = {
    .name        = "EnCo-IV-pad1",
    .key         = {0x22, 0xC2, 0x7E, 0x82, 0xB8, 0x5C, 0x15, 0xEB, 0xF6, 0x51, 0xAC, 0x90, 0xA4, 0xCD, 0xC4, 0xD8},
    .initvector  = {0xA7, 0x71, 0x62, 0x79, 0x4A, 0xC7, 0x15, 0x0C, 0x70, 0xAB, 0x0D, 0x98, 0xCE, 0x4F, 0xA1, 0x81},
    .plaintext   = {0x0B, 0xB0, 0xAA, 0x58, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64, 0x41, 0x6C, 0x77, 0x61, 
                    0x79, 0x73, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E},
    .ciphertext  = {0x45, 0xCD, 0xCD, 0x02, 0x1A, 0xEB, 0x44, 0xBE, 0x2D, 0x39, 0x7E, 0xF3, 0xB0, 0x5F, 0xA4, 0xC5, 
                    0x41, 0x09, 0x1B, 0x72, 0x7F, 0x7D, 0xCD, 0x73, 0x4B, 0xE2, 0x3D, 0x8C, 0xEC, 0xEB, 0xD4, 0x0D}
};

uint8_t buffer[32];
uint8_t buffer16[16];
Enco_MQTT_Crypto cbcAes128;

AES128 aes128;

void testCipher(const struct TestVector *test)
{
    Serial.println();
    Serial.print(test->name);
    Serial.println(" encryption test ... ");
    cbcAes128.setKey(test->key, 16);
    cbcAes128.setIV(test->initvector, 16);
    cbcAes128.encrypt(buffer, 0, test->plaintext, 16);
    if (memcmp(buffer, test->ciphertext, 16) == 0)
        Serial.println(" + + + Passed");
    else
        Serial.println(" - - - Failed");
    hexPrint(buffer,16);
}

void testCipher32(const struct TestVector32 *test)
{
    Serial.println();
    Serial.print(test->name);
    Serial.println(" encryption test ... ");
    cbcAes128.setKey(test->key, 16);
    cbcAes128.setIV(test->initvector, 16);
    cbcAes128.encrypt(buffer, 0, test->plaintext, 32);
    if (memcmp(buffer, test->ciphertext, 32) == 0)
        Serial.println(" + + + Passed");
    else
        Serial.println(" - - - Failed");
    hexPrint(buffer,32);
}

void testBlockCipher32(const struct TestVector32 *test)
{
    Serial.println();
    Serial.print(test->name);
    Serial.println(" block encryption test ... ");
    cbcAes128.setKey(test->key, 16);
    cbcAes128.setIV(test->initvector, 16);
    cbcAes128.encrypt(buffer16, 0, test->plaintext, 16);
    if (memcmp(buffer16, test->ciphertext, 16) == 0)
        Serial.println(" + + + Passed p1");
    else
        Serial.println(" - - - Failed p1");
    hexPrint(buffer16,16);
    cbcAes128.encrypt(buffer16, 0, test->plaintext+16, 16);
    if (memcmp(buffer16, test->ciphertext+16, 16) == 0)
        Serial.println(" + + + Passed p2");
    else
        Serial.println(" - - - Failed p2");
    hexPrint(buffer16,16);
}

void testToken(const struct TestVector *test, time_t epochTime, const char* password)
{
    Serial.println();
    Serial.print(test->name);
    Serial.println(" token test ... ");
    cbcAes128.setKey(test->key, 16);
    cbcAes128.setIV(test->initvector, 16);
    size_t tokenSize = cbcAes128.encryptToken(buffer, 0, epochTime, password);
    if (memcmp(buffer, test->ciphertext, tokenSize) == 0)
        Serial.print(" + + + Passed token ");
    else
        Serial.print(" - - - Failed token ");
    Serial.println(tokenSize);
    hexPrint(buffer,tokenSize);
}

void testToken32(const struct TestVector32 *test, time_t epochTime, const char* password)
{
    Serial.println();
    Serial.print(test->name);
    Serial.println(" token test ... ");
    cbcAes128.setKey(test->key, 16);
    cbcAes128.setIV(test->initvector, 16);
    size_t tokenSize = cbcAes128.encryptToken(buffer, 0, epochTime, password);
    if (memcmp(buffer, test->ciphertext, tokenSize) == 0)
        Serial.print(" + + + Passed token ");
    else
        Serial.print(" - - - Failed token ");
    Serial.println(tokenSize);
    hexPrint(buffer,tokenSize);
}

void hexPrint(byte* buffer, int len)
{
    Serial.print("0x");
    hexPrintByte(buffer[0]);
    for (int i = 1 ; i < len ; i++ ) {
      Serial.print(", 0x");
      hexPrintByte(buffer[i]);
    }
    Serial.println();  
}

void hexPrintByte(byte value)
{
  if (value < 16) {
    Serial.print('0');
  }
  Serial.print(value,HEX);
}

size_t getEncryptedTokenLength(uint8_t* theMarker, time_t epochTime, uint8_t* password, size_t len)
{
  size_t cryptoLen = len + sizeof(time_t);
  uint8_t rest = cryptoLen % 16;
  uint8_t padLen = 0;
  if (rest > 0) {
    padLen = 16 - rest;
    cryptoLen += padLen;
  }
  return cryptoLen;
}
uint8_t* getEncryptedToken(uint8_t* theMarker, time_t epochTime, uint8_t* password, size_t len)
{
//  (inc zero byte)      4-6        4               len
//  pw_len + 4 in multi 16
  
  size_t cryptoLen = len + sizeof(time_t);
  uint8_t rest = cryptoLen % 16;
  uint8_t padLen = 0;
  if (rest > 0) {
    padLen = 16 - rest;
    cryptoLen += padLen;
  }
}

void perfCipher(BlockCipher *cipher, const struct TestVector *test)
{
    unsigned long start;
    unsigned long elapsed;
    int count;

    Serial.print(test->name);
    Serial.print(" Set Key ... ");
    start = micros();
    for (count = 0; count < 10000; ++count) {
        cipher->setKey(test->key, cipher->keySize());
    }
    elapsed = micros() - start;
    Serial.print(elapsed / 10000.0);
    Serial.print("us per operation, ");
    Serial.print((10000.0 * 1000000.0) / elapsed);
    Serial.println(" per second");

    Serial.print(test->name);
    Serial.print(" Encrypt ... ");
    start = micros();
    for (count = 0; count < 5000; ++count) {
        cipher->encryptBlock(buffer, buffer);
    }
    elapsed = micros() - start;
    Serial.print(elapsed / (5000.0 * 16.0));
    Serial.print("us per byte, ");
    Serial.print((16.0 * 5000.0 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");

    Serial.print(test->name);
    Serial.print(" Decrypt ... ");
    start = micros();
    for (count = 0; count < 5000; ++count) {
        cipher->decryptBlock(buffer, buffer);
    }
    elapsed = micros() - start;
    Serial.print(elapsed / (5000.0 * 16.0));
    Serial.print("us per byte, ");
    Serial.print((16.0 * 5000.0 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");

    Serial.println();
}

void setup()
{
    Serial.begin(115200);
    while (!Serial) {
      // wait for serial port to connect. Needed for native USB
      delay(100);
    }
    Serial.println("Let's go crypto");

    Serial.println();

    Serial.println("Test Vectors:");
    testCipher(&testVectorNoIV);
    testCipher(&testVectorWithIV);
    Serial.println();

    Serial.println();
    Serial.println();
    Serial.println("Test long Vectors:");
    testCipher32(&testLongVector);
    testBlockCipher32(&testLongVector);
    Serial.println();

    Serial.println("Test token:");
    testToken(&testVectorNoIV, 2392697432, "password");
    testToken(&testVectorWithIV, 3182144088, "passwordRep");
    testToken32(&testLongVector, 1487581195, "passwordAlways");
    Serial.println();

    Serial.println("Performance Tests:");
    perfCipher(&aes128, &testVectorNoIV);
    perfCipher(&aes128, &testVectorWithIV);
    Serial.println();

    Serial.println("Finished");
}

void loop()
{
}
