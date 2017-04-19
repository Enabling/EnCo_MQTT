
/*
This example runs tests on the AES implementation to verify correct behaviour.
*/

#include <string.h>
#include "time.h"

#include "Enco_MQTT.h"

struct TestVector
{
    const char *name;
    encryption_type type;
    uint8_t key[16];
    uint8_t initvector[16];
    const time_t epochTime;
    const char* password;
    uint8_t ciphertext[52];
    const size_t tokenLength;
};

// Define the ECB test vectors from the FIPS specification.
static TestVector const testVectorNoIV = {
    .name        = "EnCo-NoIV-pad4",
    .type        = IV_ZERO,
    .key         = {0x9E, 0xDA, 0x13, 0xCA, 0x7D, 0xC2, 0xCD, 0x90,
                    0x01, 0x38, 0x21, 0x67, 0x87, 0x8B, 0x98, 0x29},
    .initvector  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    .epochTime   = 2392697432,
    .password    = "password",
    .ciphertext  = {0xE2, 0x8C, 0x80, 0x00,
                    0x5E, 0x3E, 0x7B, 0xD5, 0xF2, 0x25, 0x7D, 0x7F,
                    0xBB, 0xBE, 0x0F, 0xD9, 0xB0, 0xA5, 0x00, 0x80},
    .tokenLength = 20
};

static TestVector const testVectorWithIV = {
    .name        = "EnCo-IV-pad1",
    .type        = IV_CHANGE,
    .key         = {0x6C, 0x68, 0xE6, 0xD2, 0xA3, 0xC2, 0x52, 0x40,
                    0x90, 0xAF, 0xAF, 0x75, 0xC3, 0xC8, 0x5D, 0x7C},
    .initvector  = {0xDD, 0x40, 0x7D, 0xED, 0x26, 0xF3, 0x8C, 0xD2,
                    0x66, 0xFD, 0x58, 0x14, 0xF2, 0xAD, 0xB2, 0x27},
    .epochTime   = 3182144088, //0xBDABAA58,
    .password    = "passwordRep",
    .ciphertext  = {0xE2, 0x9A, 0xBF, 0x00,
                    0xDD, 0x40, 0x7D, 0xED, 0x26, 0xF3, 0x8C, 0xD2,
                    0x66, 0xFD, 0x58, 0x14, 0xF2, 0xAD, 0xB2, 0x27,
                    0x35, 0xFB, 0x5F, 0xAD, 0xD3, 0xF5, 0x13, 0xF5,
                    0x73, 0x47, 0xD5, 0x6F, 0x5A, 0x50, 0x7A, 0x1A},
    .tokenLength = 36
};

static TestVector const testLongVector = {
    .name        = "EnCo-IV-pad14",
    .type        = IV_REPEAT,
    .key         = {0x22, 0xC2, 0x7E, 0x82, 0xB8, 0x5C, 0x15, 0xEB, 0xF6, 0x51, 0xAC, 0x90, 0xA4, 0xCD, 0xC4, 0xD8},
    .initvector  = {0xA7, 0x71, 0x62, 0x79, 0x4A, 0xC7, 0x15, 0x0C, 0x70, 0xAB, 0x0D, 0x98, 0xCE, 0x4F, 0xA1, 0x81},
    .epochTime   = 1487581195,
    .password    = "passwordAlways",
    .ciphertext  = {0xE2, 0x99, 0xBB, 0x00,
                    0xA7, 0x71, 0x62, 0x79, 0x4A, 0xC7, 0x15, 0x0C, 0x70, 0xAB, 0x0D, 0x98, 0xCE, 0x4F, 0xA1, 0x81,
                    0x45, 0xCD, 0xCD, 0x02, 0x1A, 0xEB, 0x44, 0xBE, 0x2D, 0x39, 0x7E, 0xF3, 0xB0, 0x5F, 0xA4, 0xC5,
                    0x41, 0x09, 0x1B, 0x72, 0x7F, 0x7D, 0xCD, 0x73, 0x4B, 0xE2, 0x3D, 0x8C, 0xEC, 0xEB, 0xD4, 0x0D},
    .tokenLength = 52
};

void testToken(const struct TestVector *test)
{
    Serial.println();
    Serial.print(test->name);
    Serial.print(" @ ");
    Serial.print(test->epochTime);
    Serial.println(" token test ... ");
    Enco_MQTT_Token encoToken(test->type);
    encoToken.setKey(test->key, 16);
    if (IV_ZERO != test->type) {
      encoToken.setIV(test->initvector, 16);
      Serial.println(" set IV");
    }
    size_t tokenSize = encoToken.generate(test->epochTime, test->password);
    const uint8_t* result = encoToken.token();
    Serial.println(tokenSize);
    hexPrint(result,tokenSize);

    if ((tokenSize == test->tokenLength) &&  (memcmp(result, test->ciphertext, tokenSize) == 0))
        Serial.print(" + + + Passed token ");
    else
        Serial.print(" - - - Failed token ");
}

void hexPrint(const uint8_t* buffer, int len)
{
    Serial.print("0x");
    hexPrintByte(buffer[0]);
    for (int i = 1 ; i < len && i < MQTT_MAX_TOKEN_SIZE ; i++ ) {
//      Serial.print(", 0x");
      hexPrintByte(buffer[i]);
    }
    Serial.println();  
}

void hexPrintByte(const uint8_t value)
{
  if (value < 16) {
    Serial.print('0');
  }
  Serial.print(value,HEX);
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

    Serial.println("Test token:");
    testToken(&testVectorNoIV);
    testToken(&testVectorWithIV);
    testToken(&testLongVector);
    Serial.println();

    Serial.println("Finished");
}

void loop()
{
}
