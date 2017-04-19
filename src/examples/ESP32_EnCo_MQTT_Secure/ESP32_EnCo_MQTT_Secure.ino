/* 
 * Example code illustrating using Time library to set the time through NTP.
 * 
 * And using EnCo_Crypto to secure MQTT over plain connections.
 */ 
 
#include <TimeLib.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <PubSubClient.h>
#include "Enco_MQTT.h"
 
//-------- Customise these values -----------
// WiFi network name and password:
const char* networkName = "<< your network SSID >>";
const char* networkPswd = "<< your network password >>";

#define DEVICE_TYPE "esp8266" // use this default for quickstart or customize to your registered device
#define CC_IN_USER  "<< cc mqqt user >>"     // from your MQTT in CC definition 
#define CC_IN_PSWD  "<< cc mqqt password >>" // from your MQTT in CC definition 
#define CC_IN_TOPIC "<< cc mqqt topic >>"    // from your MQTT in CC definition 

// from your MQTT in CC definition in seperate bytes, instead of a single HEX string
uint8_t mqtt_session_key[16] = {0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9A, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0xF0};
// from your MQTT in CC definition in seperate bytes, instead of a single HEX string
uint8_t mqtt_app_key[16]     = {0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F};

//-------- Customise the above values --------

// EnCo parameters
const char mqtt_server[]     = "mqtt.enco.io"; // Should not change
const int  mqtt_port         = 1883;           // Choice between plain and secure port, here plain port, we're securing the content
const char mqtt_topic[]      = CC_IN_TOPIC;
const char mqtt_user[]       = CC_IN_USER;
const char mqtt_pswd[]       = CC_IN_PSWD;
const char mqtt_clientId[] = ("d:enco:" DEVICE_TYPE ":" CC_IN_USER);

const unsigned long DEFAULT_TIME = 1487250483; // Jan 1 2013

// NTP Servers:
static const char ntpServerName[] = "pool.ntp.org";
//static const char ntpServerName[] = "europe.pool.ntp.org";
//static const char ntpServerName[] = "us.pool.ntp.org";
//static const char ntpServerName[] = "time.nist.gov";

const int timeZone = 1;     // Central European Time
const int syncInterval = 60 * 60 * 12; // Sync every 12 hours

const int LED_PIN = 5;

WiFiUDP Udp;
unsigned int localPort = 8888;  // local port to listen for UDP packets

WiFiClient wifiClient;
PubSubClient client(mqtt_server, mqtt_port, wifiClient);
Enco_MQTT_Token encoToken(IV_CHANGE);
Enco_MQTT_Payload encoPayload(IV_CHANGE);

void setup()  {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  encoToken.setKey(mqtt_session_key, sizeof(mqtt_session_key));
  encoPayload.setKey(mqtt_app_key, sizeof(mqtt_app_key));
  while (!Serial) ; // Needed for native serial over USB

  // Connect to the WiFi network (see function below loop)
  connectToWiFi(networkName, networkPswd);

  Serial.print("IP number assigned by DHCP is ");
  Serial.println(WiFi.localIP());
  Serial.println("Starting UDP");
  Udp.begin(localPort);
  digitalWrite(LED_PIN, LOW);  // LED off initialy
  setSyncProvider(getNtpTime);  //set function to call when sync required
  setSyncInterval(syncInterval);   
  Serial.println("Setup done");
}

void loop(){    
  if (timeStatus()== timeSet) {
    digitalWrite(LED_PIN, HIGH); // LED on if synced
    digitalClockDisplay();
    testMQTT();
  } else {
    digitalWrite(LED_PIN, LOW);  // LED off if needs refresh
    syncTime();
  }
  delay(10000);
}

void connectToWiFi(const char * ssid, const char * pwd)
{
  int ledState = 0;

  Serial.println();
  Serial.println("Connecting to WiFi network: " + String(ssid));

  WiFi.begin(ssid, pwd);

  while (WiFi.status() != WL_CONNECTED) 
  {
    // Blink LED while we're connecting:
    digitalWrite(LED_PIN, ledState);
    ledState = (ledState + 1) % 2; // Flip ledState
    delay(500);
    Serial.print(".");
  }

  Serial.println();
  Serial.println("WiFi connected!");
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());
}

void digitalClockDisplay(){
  time_t timeVal = now();
  time_t localTimeVal = timeVal + timeZone * SECS_PER_HOUR;
  // digital clock display of the time
  Serial.print(hour());
  printDigits(minute());
  printDigits(second());
  Serial.print(" ");
  Serial.print(day());
  Serial.print(" ");
  Serial.print(month());
  Serial.print(" ");
  Serial.print(year()); 
  Serial.print(" 0x");
  Serial.print(timeVal, HEX);
  Serial.println(); 
}

void printDigits(int digits){
  // utility function for digital clock display: prints preceding colon and leading 0
  Serial.print(":");
  if(digits < 10)
    Serial.print('0');
  Serial.print(digits);
}

void syncTime() {
    Serial.print(ntpServerName);
    Serial.println(" - Try NTP");
    time_t gotNow = getNtpTime();
    Serial.println(gotNow);
    if( gotNow >= DEFAULT_TIME) { // check the integer is a valid time (greater than Jan 1 2013)
      setTime(gotNow);  // Sync Arduino clock to the time received
      digitalClockDisplay();
    }  
}

void testMQTT() {
 if (!!!client.connected()) {
   Serial.print("Reconnecting client to "); Serial.println(mqtt_server);
   uint16_t userSize = strlen(mqtt_user);
   uint16_t tokenSize = encoToken.generate(now(), mqtt_pswd);
   uint16_t pswdSize = strlen(mqtt_pswd);
   while (!!!client.connect(mqtt_clientId, mqtt_user, userSize, (const char*) encoToken.token(), tokenSize)) {
     Serial.print(".");
     delay(500);
   }
   Serial.println();
 }

 String payload = "{\"counter\":";
 payload += millis()/1000;
 payload += "}";
 
 Serial.print("Encrypting payload: "); Serial.println(payload);
 uint16_t payloadSize = encoPayload.generate(payload.c_str());

 if (client.publish(mqtt_topic, encoPayload.payload(), payloadSize)) {
   Serial.println("Publish ok");
 } else {
   Serial.println("Publish failed");
 }
}
/*-------- NTP code ----------*/

const int NTP_PACKET_SIZE = 48; // NTP time is in the first 48 bytes of message
byte packetBuffer[NTP_PACKET_SIZE]; //buffer to hold incoming & outgoing packets

time_t getNtpTime()
{
  IPAddress ntpServerIP; // NTP server's ip address

  while (Udp.parsePacket() > 0) ; // discard any previously received packets
  Serial.println("Transmit NTP Request");
  // get a random server from the pool
  WiFi.hostByName(ntpServerName, ntpServerIP);
  Serial.print(ntpServerName);
  Serial.print(": ");
  Serial.println(ntpServerIP);
  sendNTPpacket(ntpServerIP);
  uint32_t beginWait = millis();
  while (millis() - beginWait < 1500) {
    int size = Udp.parsePacket();
    if (size >= NTP_PACKET_SIZE) {
      Serial.println("Receive NTP Response");
      Udp.read(packetBuffer, NTP_PACKET_SIZE);  // read packet into the buffer
      unsigned long secsSince1900;
      // convert four bytes starting at location 40 to a long integer
      secsSince1900 =  (unsigned long)packetBuffer[40] << 24;
      secsSince1900 |= (unsigned long)packetBuffer[41] << 16;
      secsSince1900 |= (unsigned long)packetBuffer[42] << 8;
      secsSince1900 |= (unsigned long)packetBuffer[43];
      return secsSince1900 - 2208988800UL; // + timeZone * SECS_PER_HOUR;
    }
  }
  Serial.println("No NTP Response :-(");
  return 0; // return 0 if unable to get the time
}

// send an NTP request to the time server at the given address
void sendNTPpacket(IPAddress &address)
{
  // set all bytes in the buffer to 0
  memset(packetBuffer, 0, NTP_PACKET_SIZE);
  // Initialize values needed to form NTP request
  // (see URL above for details on the packets)
  packetBuffer[0] = 0b11100011;   // LI, Version, Mode
  packetBuffer[1] = 0;     // Stratum, or type of clock
  packetBuffer[2] = 6;     // Polling Interval
  packetBuffer[3] = 0xEC;  // Peer Clock Precision
  // 8 bytes of zero for Root Delay & Root Dispersion
  packetBuffer[12] = 49;
  packetBuffer[13] = 0x4E;
  packetBuffer[14] = 49;
  packetBuffer[15] = 52;
  // all NTP fields have been given values, now
  // you can send a packet requesting a timestamp:
  Udp.beginPacket(address, 123); //NTP requests are to port 123
  Udp.write(packetBuffer, NTP_PACKET_SIZE);
  Udp.endPacket();
}
