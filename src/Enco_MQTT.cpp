/*
 Enco_MQTT.cpp - Token and payload functions for secure MQTT with EnCo.
  Proximus EnCo
  https://enco.io
*/

#include "Arduino.h"
#include "Enco_Crypto.h"
#include "Enco_MQTT.h"

	
Enco_MQTT_Token::Enco_MQTT_Token(encryption_type type) {
	crypto.clean();
	marker[0] = 0xE2;
	switch (type) {
		case IV_ZERO : 
			marker[1] = 0x8C;
			marker[2] = 0x80;
			clearIV = true;
			break;
		case IV_REPEAT :
			marker[1] = 0x99;
			marker[2] = 0xBB;
			clearIV = false;
			break;
		default :
			marker[1] = 0x9A;
			marker[2] = 0xBF;
			clearIV = false;
			break;
	}
	marker[3] = 0x00;
}

Enco_MQTT_Token::~Enco_MQTT_Token() {
	clean();
}

void Enco_MQTT_Token::clean() {
	crypto.clean();
	memset(_token, 0, sizeof(_token));
	_length = 0;
}

size_t Enco_MQTT_Token::keySize() const {
	return crypto.keySize();
}

bool Enco_MQTT_Token::setKey(const uint8_t *key, size_t len) {
    return crypto.setKey(key, len);
}

bool Enco_MQTT_Token::setIV(const uint8_t *iv, size_t len) {
    return crypto.setIV(iv, len);
}

size_t Enco_MQTT_Token::generate(time_t epochTime, const char* pass) {

#ifdef MQTT_BIG_ENDIAN
    _token[0] = 0xFE;
	_token[1] = 0xFF;
	uint8_t* working = _token + 2;
	memcpy(working, marker, sizeof(marker));
	size_t offset = 2 + sizeof(marker);
#else
	size_t offset = sizeof(marker);
	memcpy(_token, marker, sizeof(marker));
#endif

    if (clearIV) {
		crypto.clean();
	} else {
		offset = crypto.getIV(_token, offset);
	}
	uint8_t len = 4;
	memcpy(buffer, &epochTime, len);
	while (*pass != 0) {
		buffer[len++] = *pass++;
		if (len >= 16) {
			offset = crypto.encrypt(_token, offset, buffer, len);
			len = 0;
		}
	}
	if (len > 0) {
		offset = crypto.encrypt(_token, offset, buffer, len);
	}
	memset(buffer, 0, sizeof(buffer));
	return (_length = offset);
}


Enco_MQTT_Payload::Enco_MQTT_Payload(encryption_type type) {
	this->type = type;
	crypto.clean();
}

Enco_MQTT_Payload::~Enco_MQTT_Payload() {
	clean();
}

void Enco_MQTT_Payload::clean() {
	crypto.clean();
	memset(_payload, 0, sizeof(_payload));
	memset(iv, 0, sizeof(iv));
	_length = 0;
}

size_t Enco_MQTT_Payload::keySize() const {
	return crypto.keySize();
}

bool Enco_MQTT_Payload::setKey(const uint8_t *key, size_t len) {
    return crypto.setKey(key, len);
}

bool Enco_MQTT_Payload::setIV(const uint8_t *iv, size_t len) {
    memcpy(this->iv, iv, 16);
    return crypto.setIV(iv, len);
}

size_t Enco_MQTT_Payload::generate(const char* payload) {
    return generate((const uint8_t*)payload,strlen(payload));
}

size_t Enco_MQTT_Payload::generate(const uint8_t *payload, size_t len) {

    size_t offset = _length = 0;
	switch (type) {
		case IV_ZERO : 
		    crypto.clean();
			break;
		case IV_REPEAT :
			crypto.setIV(iv, sizeof(iv));
			break;
		default :
		    offset = crypto.getIV(_payload, offset);
			break;
	}

	while (len >= 16) {
		offset = crypto.encrypt(_payload, offset, payload, 16);
		payload += 16;
		len -= 16;
	}
	if (len > 0) {
		offset = crypto.encrypt(_payload, offset, payload, len);
	}
	return (_length = offset);

}

