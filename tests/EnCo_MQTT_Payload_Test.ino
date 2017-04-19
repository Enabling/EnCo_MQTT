
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
    const char* payload;
    uint8_t ciphertext[52];
    const size_t payloadLength;
};

// Define the ECB test vectors from the FIPS specification.
static TestVector const testVectorNoIV = {
    .name        = "EnCo-NoIV",
    .type        = IV_ZERO,
    .key         = {0x9E, 0xDA, 0x13, 0xCA, 0x7D, 0xC2, 0xCD, 0x90,
                    0x01, 0x38, 0x21, 0x67, 0x87, 0x8B, 0x98, 0x29},
    .initvector  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    .payload     = "{count:1}",
    .ciphertext  = {0xA0, 0x98, 0x64, 0xB7, 0x61, 0x0F, 0xC5, 0x91, 
                    0x19, 0xB7, 0x61, 0xF3, 0xE3, 0xB9, 0x99, 0x4E},
    .payloadLength = 16
};

static TestVector const testVectorWithIV = {
    .name        = "EnCo-IV",
    .type        = IV_CHANGE,
    .key         = {0x6C, 0x68, 0xE6, 0xD2, 0xA3, 0xC2, 0x52, 0x40,
                    0x90, 0xAF, 0xAF, 0x75, 0xC3, 0xC8, 0x5D, 0x7C},
    .initvector  = {0xDD, 0x40, 0x7D, 0xED, 0x26, 0xF3, 0x8C, 0xD2,
                    0x66, 0xFD, 0x58, 0x14, 0xF2, 0xAD, 0xB2, 0x27},
    .payload     = "{count:2}",
    .ciphertext  = {0xDD, 0x40, 0x7D, 0xED, 0x26, 0xF3, 0x8C, 0xD2,
                    0x66, 0xFD, 0x58, 0x14, 0xF2, 0xAD, 0xB2, 0x27,
                    0xFF, 0x71, 0x30, 0x32, 0x34, 0xFE, 0x03, 0x65, 
                    0xF4, 0x3D, 0x85, 0xC1, 0x77, 0x1A, 0xF2, 0xF4},
    .payloadLength = 32
};

static TestVector const testLongVector = {
    .name        = "EnCo-IV-pad14",
    .type        = IV_REPEAT,
    .key         = {0x22, 0xC2, 0x7E, 0x82, 0xB8, 0x5C, 0x15, 0xEB, 0xF6, 0x51, 0xAC, 0x90, 0xA4, 0xCD, 0xC4, 0xD8},
    .initvector  = {0xA7, 0x71, 0x62, 0x79, 0x4A, 0xC7, 0x15, 0x0C, 0x70, 0xAB, 0x0D, 0x98, 0xCE, 0x4F, 0xA1, 0x81},
    .payload     = "{name: 123456488, count:333455568}",
    .ciphertext  = {0x82, 0xD7, 0xE5, 0xE6, 0x32, 0x27, 0x42, 0x71, 0x88, 0x00, 0x0F, 0x8A, 0x3D, 0x8D, 0x31, 0x29, 
                    0x03, 0x03, 0xBE, 0x44, 0xF3, 0xFB, 0xF5, 0x13, 0xDB, 0xEC, 0x28, 0x87, 0x19, 0x4E, 0xC2, 0x49, 
                    0xBB, 0xCB, 0xD6, 0x02, 0x0A, 0xB8, 0x77, 0x56, 0xA0, 0x34, 0x1C, 0x7D, 0x08, 0xD4, 0x4D, 0xA1},
    .payloadLength = 48
};

void testPayload(const struct TestVector *test)
{
    Serial.println();
    Serial.print(test->name);
    Serial.println(" payload test ... ");
    Enco_MQTT_Payload encoPayload(test->type);
    encoPayload.setKey(test->key, 16);
    if (IV_ZERO != test->type) {
      encoPayload.setIV(test->initvector, 16);
      Serial.println(" set IV");
    }
    size_t payloadSize = encoPayload.generate(test->payload);
    const uint8_t* result = encoPayload.payload();
    Serial.println(payloadSize);
    hexPrint(result,payloadSize);

    if (payloadSize == test->payloadLength) {
      if (memcmp(result, test->ciphertext, payloadSize) == 0) {
        Serial.println(" + + + Passed payload ");
        payloadSize = encoPayload.generate(test->payload);
        result = encoPayload.payload();
        if (payloadSize != test->payloadLength) {
           Serial.println(" - - - Failed payload size run 2");
        } else {
          if (IV_CHANGE == test->type) { // Change has to be different
            if (memcmp(result, test->ciphertext, payloadSize) == 0)
              Serial.println(" - - - Failed payload run 2");
            else
              Serial.println(" + + + Passed payload run 2");
          } else { // ZERO and REPEAT have to be repeatable
            if (memcmp(result, test->ciphertext, payloadSize) == 0)
              Serial.println(" + + + Passed payload run 2");
            else
              Serial.println(" - - - Failed payload run 2");
          }
        }
      } else
        Serial.println(" - - - Failed payload");
    }
    else
        Serial.println(" - - - Failed payload size");
}

void hexPrint(const uint8_t* buffer, int len)
{
    Serial.print("0x");
    hexPrintByte(buffer[0]);
    for (int i = 1 ; i < len && i < MQTT_MAX_PAYLOAD_SIZE ; i++ ) {
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
    Serial.println("Let's go payload crypto");

    Serial.println();

    Serial.println("Test payload:");
    testPayload(&testVectorNoIV);
    testPayload(&testVectorWithIV);
    testPayload(&testLongVector);
    Serial.println();

    Serial.println("Finished");
}

void loop()
{
}
