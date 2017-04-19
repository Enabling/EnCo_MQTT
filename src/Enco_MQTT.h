/*
 Enco_MQTT.h - Token and payload functions for secure MQTT with EnCo.
  Proximus EnCo
  https://enco.io
*/

#ifndef Enco_MQTT_Token_h
#define Enco_MQTT_Token_h

//#define MQTT_BIG_ENDIAN

// MQTT_MAX_PASSWORD_SIZE : Maximum password length in bytes.
// Should be 4 less than a multiple of 16
#ifndef MQTT_MAX_PASSWORD_LENGTH
#define MQTT_MAX_PASSWORD_LENGTH 28
#endif

// MQTT_MAX_TOKEN_SIZE : Maximum token size ('marker' 6  + 'IV' 16 + 'time' 4 + MQTT_MAX_PASSWORD_LENGTH)
#ifndef MQTT_MAX_TOKEN_SIZE
#define MQTT_MAX_TOKEN_SIZE (26 + MQTT_MAX_PASSWORD_LENGTH)
#endif

// MQTT_MAX_PACKET_SIZE : Maximum packet size
#ifndef MQTT_MAX_PAYLOAD_SIZE
#ifdef MQTT_MAX_PACKET_SIZE
#define MQTT_MAX_PAYLOAD_SIZE MQTT_MAX_PACKET_SIZE
#else
#define MQTT_MAX_PAYLOAD_SIZE 128
#endif
#endif

#include <Arduino.h>
#include "Enco_Crypto.h"

typedef enum {
    IV_ZERO,
    IV_REPEAT,
    IV_CHANGE
} encryption_type;


class Enco_MQTT_Token {
private:
    Enco_Crypto crypto;
	uint8_t marker[4];
	bool clearIV;
    uint8_t buffer[16];
    uint8_t _token[MQTT_MAX_TOKEN_SIZE];
	size_t _length;
	void clean();
public:
    Enco_MQTT_Token(encryption_type);
    virtual ~Enco_MQTT_Token();

    size_t keySize() const;

    bool setKey(const uint8_t *key, size_t len);
    bool setIV(const uint8_t *iv, size_t len);

	const uint8_t* token() { return _token; };
	size_t length() { return _length; };

    size_t generate(time_t epochTime, const char* pass);

};

class Enco_MQTT_Payload {
private:
    Enco_Crypto crypto;
	encryption_type type;
    uint8_t buffer[16];
    uint8_t iv[16];
    uint8_t _payload[MQTT_MAX_PAYLOAD_SIZE];
	size_t _length;
	void clean();
public:
    Enco_MQTT_Payload(encryption_type);
    virtual ~Enco_MQTT_Payload();

    size_t keySize() const;

    bool setKey(const uint8_t *key, size_t len);
    bool setIV(const uint8_t *iv, size_t len);

	const uint8_t* payload() { return _payload; };
	size_t length() { return _length; };

    size_t generate(const char* payload);
    size_t generate(const uint8_t *payload, size_t len);

};


#endif
