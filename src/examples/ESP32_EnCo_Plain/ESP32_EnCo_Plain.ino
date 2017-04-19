/**
 * Helloworld style, connect an ESP32 to EnCo Platform with MQTT
 * 
 */

#include <WiFi.h>
#include <PubSubClient.h>

//-------- Customise these values -----------
const char* networkName = "<< your network SSID >>";
const char* networkPswd = "<< your network password >>";

#define DEVICE_TYPE "esp32" // use this default for quickstart or customize to your registered device
#define CC_IN_USER  "<< cc mqqt user >>"     // from your MQTT in CC definition 
#define CC_IN_PSWD  "<< cc mqqt password >>" // from your MQTT in CC definition 
#define CC_IN_TOPIC "<< cc mqqt topic >>"    // from your MQTT in CC definition 

//-------- Customise the above values --------

char server[] = "mqtt.enco.io";
char topic[]  = CC_IN_TOPIC;
char mqtt_user[] = CC_IN_USER;
char mqtt_pswd[] = CC_IN_PSWD;
char clientId[]  = "d:enco:" DEVICE_TYPE ":" CC_IN_USER;

WiFiClient wifiClient;
PubSubClient client(server, 1883, wifiClient);

void setup() {

 Serial.begin(115200);
 while (!Serial) ; // Needed for native serial over USB

 initWiFi();
}

void loop() {

 if (!!!client.connected()) {
   Serial.print("Reconnecting client to "); Serial.println(server);
   while (!!!client.connect(clientId, mqtt_user, mqtt_pswd)) {
     Serial.print(".");
     delay(500);
   }
   Serial.println();
 }

 String payload = "{\"counter\":";
 payload += millis()/1000;
 payload += "}";
 
 Serial.print("Sending payload: "); Serial.println(payload);
 
 if (client.publish(topic, (char*) payload.c_str())) {
   Serial.println("Publish ok");
 } else {
   Serial.println("Publish failed");
 }

 delay(3000);
}

void initWiFi() {
 Serial.print("Connecting to "); Serial.print(networkName);
 if (strcmp (WiFi.SSID().c_str(), networkName) != 0) {
   WiFi.begin(networkName, networkPswd);
 }
 while (WiFi.status() != WL_CONNECTED) {
   delay(500);
   Serial.print(".");
 } 
 Serial.println(""); Serial.print("WiFi connected, IP address: "); Serial.println(WiFi.localIP());
}
