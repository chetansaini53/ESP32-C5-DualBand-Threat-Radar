/*
 * ============================================================================
 *  WIRELESS THREAT RADAR  —  ESP32-C5 DUAL-BAND (2.4 + 5 GHz)  +  1.3" OLED
 * ============================================================================
 *  DETECTION-ONLY radar. A passive monitor that flags nearby wireless attacks
 *  on a 128x64 mono OLED in real time. It never attacks — it only listens and
 *  alerts. Dual-band ESP32-C5, single radio, time-sliced cycle:
 *    PHASE A  WiFi promiscuous -> DEAUTH/DISASSOC attacks (>10/s from one src =
 *             ALERT) + PWNAGOTCHI beacons (MAC de:ad:be:ef:de:ad). Hops BOTH
 *             2.4GHz (ch 1-13) AND 5GHz (ch 36-165). cyberac1d presence beacon
 *             on 2.4GHz only (5GHz TX skipped for DFS/regulatory safety).
 *    PHASE B  BLE passive scan -> device count + advertisement FLOOD/SPAM.
 *    ZIGBEE   deferred (802.15.4 needs WiFi off -> coexist).
 *  OLED shows live SECURE / THREAT status; flips to a full inverted ALERT
 *  screen on an attack with attacker + target MAC, channel and band.
 *
 *  THE 5GHz KEY: on the C5, esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO) MUST be
 *  called once at boot, else esp_wifi_set_channel() rejects 5GHz channels with
 *  ESP_ERR_NOT_SUPPORTED. The on-screen "5g" counter proves 5GHz frames arrive.
 *
 *  Hardware : ESP32-C5 dev board + 1.3" I2C OLED (SH1106 or SSD1306, 128x64)
 *  Wiring   : OLED SDA->GPIO4  SCL->GPIO5  VCC->3V3  GND->GND  (SW I2C)
 *  Build    : arduino-esp32 core 3.3.x (IDF 5.5) | FQBN esp32:esp32:esp32c5
 *  Library  : U8g2 (mono OLED)
 *
 *  Authors  : Chetan Saini (@cyberac1d)  &  Ella (AI pair-partner)
 *  License  : MIT
 *  Purpose  : Educational / defensive security. Use only on networks and
 *             devices you own or are explicitly authorized to test.
 * ============================================================================
 */
#include <U8g2lib.h>
#include <Wire.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <string.h>

// Defined up here (before any function) so Arduino's auto-generated prototypes,
// which it injects near the top, can see the type. dual-band hop entry:
// txOk = 2.4GHz only -> the cyberac1d beacon (2.4GHz DS-param IE) is valid +
// regulatory-safe there; on 5GHz we LISTEN only (passive RX is fine anywhere).
struct Hop { uint8_t ch; bool band5; bool txOk; };

// ---------------- OLED 1.3" (SH1106 is most common at 1.3"; SSD1306 fallback) -------
// SW (bit-banged) I2C works on ANY GPIO -> robust on a new chip with custom pins.
// C5 pin hazards: GPIO4/5=LP-UART, GPIO6-10=flash/SDIO (FSPI), 7/25/26/27/28=strapping,
// 11/12=UART0, 13/14=USB. GPIO23/24 are free (no secondary fn, on J3) -> safe for SW I2C.
#define OLED_SDA 23
#define OLED_SCL 24
U8G2_SH1106_128X64_NONAME_F_SW_I2C u8g2(U8G2_R0, OLED_SCL, OLED_SDA, U8X8_PIN_NONE);
// If the panel shows shifted/garbled pixels it's an SSD1306 -> comment the line
// above and uncomment the one below:
// U8G2_SSD1306_128X64_NONAME_F_SW_I2C u8g2(U8G2_R0, OLED_SCL, OLED_SDA, U8X8_PIN_NONE);

// OLED presence detected at boot via I2C scan -> radar runs HEADLESS (serial only)
// if the panel is absent/miswired, so 5GHz detection never blocks on the display.
static bool    oledOK   = false;
static uint8_t oledAddr = 0x3C;
// safe I2C-capable GPIOs on the C5 (NO flash 6-11, USB 13/14, UART0 11/12, strapping 7/25-28)
static const uint8_t I2C_CAND[] = {23,24,22,21,20,19,18,17,16,15,1,0,2,3,4,5};
static const int NCAND = (int)(sizeof(I2C_CAND)/sizeof(I2C_CAND[0]));

// ---------------- shared detector state (cb -> loop) ----------------
struct DeauthEvt { uint8_t src[6]; uint8_t dst[6]; int8_t rssi; uint8_t ch; uint8_t subtype; };
#define RING 48
static volatile DeauthEvt ring[RING];
static volatile uint16_t  ringHead = 0;     // cb writes
static uint16_t           ringTail = 0;     // loop reads
static volatile uint32_t  g_deauthTotal = 0;
static volatile uint32_t  g_mgmtSeen = 0;   // ALL mgmt frames seen (sniffer alive)
static volatile uint32_t  g_rx5g = 0;       // mgmt frames seen on a 5GHz channel

static volatile uint32_t  g_pwnCount = 0;
static volatile int8_t    g_pwnRssi  = 0;
static volatile uint32_t  g_pwnLastMs = 0;
static volatile uint8_t   g_pwnMac[6] = {0};

static const uint8_t PWN_MAC[6] = {0xde,0xad,0xbe,0xef,0xde,0xad};

// BLE counters (written from BLE task)
static volatile uint32_t g_bleAdv = 0;
static volatile uint32_t g_bleSpamCID = 0;

// ---------------- cyberac1d presence beacon (2.4GHz only; built once) ----------------
static uint8_t beacon[] = {
  0x80,0x00, 0x00,0x00,
  0xff,0xff,0xff,0xff,0xff,0xff,            // DA broadcast
  0xc6,0xac,0x1d,0x13,0x37,0x01,            // SA (locally-administered)
  0xc6,0xac,0x1d,0x13,0x37,0x01,            // BSSID = SA
  0x00,0x00,                                // seq (driver fills)
  0,0,0,0,0,0,0,0,                          // timestamp
  0x64,0x00,                                // beacon interval
  0x21,0x04,                                // capability (ESS, short preamble, OPEN)
  0x00,0x19,'D','M',' ','c','y','b','e','r','a','c','1','d',' ','o','n',' ','I','n','s','t','a','g','r','a','m', // SSID IE (25)
  0x03,0x01,0x01,                           // DS param (channel byte at idx 65)
  0x01,0x08,0x82,0x84,0x8b,0x96,0x24,0x30,0x48,0x6c // supported rates
};
#define BEACON_CHAN_IDX 65

// ---------------- WiFi sniffer callback (IRAM, minimal!) ----------------
void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  g_mgmtSeen++;
  const wifi_promiscuous_pkt_t *ppkt = (const wifi_promiscuous_pkt_t *)buf;
  if (ppkt->rx_ctrl.channel > 14) g_rx5g++;          // 5GHz proof-of-life counter
  const uint8_t *p = ppkt->payload;
  uint8_t fc = p[0];
  if (fc == 0xC0 || fc == 0xA0) {                    // deauth(0xC0) / disassoc(0xA0)
    uint16_t h = ringHead;
    volatile DeauthEvt &e = ring[h % RING];
    for (int i=0;i<6;i++){ e.src[i]=p[10+i]; e.dst[i]=p[4+i]; }
    e.rssi = ppkt->rx_ctrl.rssi; e.ch = ppkt->rx_ctrl.channel;
    e.subtype = (fc==0xC0)?0x0C:0x0A;
    ringHead = h + 1;
    g_deauthTotal++;
  } else if (fc == 0x80) {                           // beacon -> pwnagotchi?
    if (memcmp((const void*)&p[10], PWN_MAC, 6) == 0 || memcmp((const void*)&p[16], PWN_MAC, 6) == 0) {
      g_pwnCount++;
      g_pwnRssi = ppkt->rx_ctrl.rssi;
      g_pwnLastMs = millis();
      for (int i=0;i<6;i++) g_pwnMac[i]=p[10+i];
    }
  }
}

// ---------------- BLE scan callback (BLE task, tally only) ----------------
class BLECB : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice d) override {
    g_bleAdv++;
    if (d.haveManufacturerData()) {
      String md = d.getManufacturerData();
      if (md.length() >= 2) {
        uint16_t cid = (uint8_t)md[0] | ((uint8_t)md[1] << 8);
        if (cid==0x004C || cid==0x0006 || cid==0x00E0) g_bleSpamCID++;  // Apple/MS/Google
      }
    }
  }
};
static BLEScan *pScan = nullptr;

// ---------------- aggregated attacker table (loop) ----------------
struct Src { uint8_t mac[6]; uint8_t victim[6]; uint16_t win; uint32_t winStart; uint32_t total; uint32_t lastMs; int8_t rssi; uint8_t ch; bool used; bool attacking; };
#define MAXSRC 12
static Src srcs[MAXSRC];

static uint32_t bleUnique = 0, bleAdvLast = 0; static bool bleSpam = false;
static bool alertActive = false; static uint32_t alertUntil = 0;
static char alertProto[20] = ""; static uint8_t alertMac[6]={0}, alertVic[6]={0};
static int8_t alertRssi=0; static uint8_t alertCh=0;

static int findSrc(const uint8_t *mac) {
  int freeI = -1;
  for (int i=0;i<MAXSRC;i++){
    if (srcs[i].used && memcmp(srcs[i].mac,mac,6)==0) return i;
    if (!srcs[i].used && freeI<0) freeI=i;
  }
  if (freeI<0) { // evict oldest
    uint32_t oldest=0xFFFFFFFF; for(int i=0;i<MAXSRC;i++) if(srcs[i].lastMs<oldest){oldest=srcs[i].lastMs;freeI=i;}
  }
  memset(&srcs[freeI],0,sizeof(Src)); memcpy(srcs[freeI].mac,mac,6); srcs[freeI].used=true; srcs[freeI].winStart=millis();
  return freeI;
}

static void drainRing(uint32_t now) {
  while (ringTail != ringHead) {
    volatile DeauthEvt &e = ring[ringTail % RING];
    uint8_t mac[6],vic[6]; for(int i=0;i<6;i++){mac[i]=e.src[i];vic[i]=e.dst[i];}
    int8_t rssi=e.rssi; uint8_t ch=e.ch;
    ringTail++;
    int s = findSrc(mac);
    if (now - srcs[s].winStart > 1000) { srcs[s].winStart=now; srcs[s].win=0; }
    srcs[s].win++; srcs[s].total++; srcs[s].lastMs=now; srcs[s].rssi=rssi; srcs[s].ch=ch;
    memcpy(srcs[s].victim,vic,6);
    if (srcs[s].win >= 11) {                          // >10 deauth/sec from same src = ATTACK
      srcs[s].attacking = true;
      alertActive=true; alertUntil=now+5000; strcpy(alertProto,"WIFI DEAUTH");
      memcpy(alertMac,mac,6); memcpy(alertVic,vic,6); alertRssi=rssi; alertCh=ch;
    }
  }
  for (int i=0;i<MAXSRC;i++){ if(srcs[i].used && now-srcs[i].lastMs>8000){srcs[i].used=false;srcs[i].attacking=false;} }
}

static int activeAttackers() { int n=0; for(int i=0;i<MAXSRC;i++) if(srcs[i].used && srcs[i].attacking) n++; return n; }
static int seenSources()     { int n=0; for(int i=0;i<MAXSRC;i++) if(srcs[i].used) n++; return n; }

// ---------------- dual-band hop plan ----------------
static const Hop HOPS[] = {
  {1,false,true},{2,false,true},{3,false,true},{4,false,true},{5,false,true},
  {6,false,true},{7,false,true},{8,false,true},{9,false,true},{10,false,true},
  {11,false,true},{12,false,true},{13,false,true},
  {36,true,false},{40,true,false},{44,true,false},{48,true,false},      // UNII-1
  {149,true,false},{153,true,false},{157,true,false},{161,true,false},{165,true,false} // UNII-3
};
static const int NHOP = (int)(sizeof(HOPS)/sizeof(HOPS[0]));

// ---------------- display (U8g2 full-buffer, mono 128x64) ----------------
static void macStr(char *o, const uint8_t *m){ sprintf(o,"%02X:%02X:%02X:%02X:%02X:%02X",m[0],m[1],m[2],m[3],m[4],m[5]); }
static int lastThreat = -1;

static void drawNormal(const char *phase, const Hop &h) {
  uint32_t now = millis();
  int atk = activeAttackers();
  bool pwn = (now-g_pwnLastMs<8000 && g_pwnCount>0);
  bool threat = (atk>0) || pwn || bleSpam;
  char b[40];

  u8g2.clearBuffer();
  // title row
  u8g2.setFont(u8g2_font_6x10_tf);
  u8g2.drawStr(2, 9, "THREAT RADAR");
  u8g2.setFont(u8g2_font_5x7_tf);
  u8g2.drawStr(96, 8, "2.4+5G");
  u8g2.drawHLine(0, 11, 128);

  // big status banner (THREAT = inverted box)
  if (threat) {
    u8g2.drawBox(0, 13, 128, 22);
    u8g2.setDrawColor(0);
    u8g2.setFont(u8g2_font_logisoso16_tr);
    u8g2.drawStr(16, 32, "THREAT");
    u8g2.setDrawColor(1);
  } else {
    u8g2.setFont(u8g2_font_logisoso16_tr);
    u8g2.drawStr(20, 32, "SECURE");
  }
  u8g2.drawHLine(0, 37, 128);

  // compact stats
  u8g2.setFont(u8g2_font_5x8_tf);
  sprintf(b, "WIFI atk:%d src:%d", atk, seenSources());
  u8g2.drawStr(2, 46, b);
  if (pwn) sprintf(b, "PWN:FOUND %d  BLE:%lu", g_pwnRssi, (unsigned long)bleUnique);
  else     sprintf(b, "PWN:clear  BLE:%lu%s", (unsigned long)bleUnique, bleSpam?" !":"");
  u8g2.drawStr(2, 55, b);
  // footer = the proof line: current ch + band + total rx + 5GHz rx
  sprintf(b, "c%d %s rx%lu 5g%lu", h.ch, h.band5?"5G":"24",
          (unsigned long)g_mgmtSeen, (unsigned long)g_rx5g);
  u8g2.drawStr(2, 63, b);
  u8g2.sendBuffer();
}

static void drawAlert() {
  uint32_t now = millis(); char b[40], line[40];
  bool blink = (now/300)%2;
  u8g2.clearBuffer();
  // inverted top bar
  u8g2.drawBox(0, 0, 128, 13);
  u8g2.setDrawColor(0);
  u8g2.setFont(u8g2_font_6x10_tf);
  u8g2.drawStr(38, 10, "! ALERT !");
  u8g2.setDrawColor(1);
  // protocol (big, blinks)
  if (blink) { u8g2.setFont(u8g2_font_logisoso16_tr); u8g2.drawStr(2, 32, alertProto); }
  // attacker / victim / meta
  u8g2.setFont(u8g2_font_5x8_tf);
  macStr(b, alertMac); snprintf(line, sizeof(line), "ATK %s", b); u8g2.drawStr(2, 44, line);
  bool hasVic=false; for(int i=0;i<6;i++) if(alertVic[i]) hasVic=true;
  if (hasVic) { macStr(b, alertVic); snprintf(line, sizeof(line), "VIC %s", b); u8g2.drawStr(2, 53, line); }
  snprintf(line, sizeof(line), "ch%d %s rssi%d x%d", alertCh, alertCh>14?"5G":"24", alertRssi, activeAttackers());
  u8g2.drawStr(2, 63, line);
  u8g2.sendBuffer();
}

// ---------------- cycle ----------------
enum { PH_WIFI, PH_BLE };
static int phase = PH_WIFI;
static int hopIdx = 0;
static uint32_t phaseStart=0,lastHop=0,lastBeacon=0,lastDraw=0,lastLog=0;

static void wifiPromiscOn(bool on){ esp_wifi_set_promiscuous(on); }
static void hopTo(int idx){ esp_wifi_set_channel(HOPS[idx].ch, WIFI_SECOND_CHAN_NONE); }

void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println("\n[boot] threat radar C5 dual-band"); Serial.flush();

  // --- AUTO-FIND the OLED across safe GPIO pairs (handles clone-board pinouts +
  //     swapped SDA/SCL). Only SAFE pins are probed -> flash pins never touched. ---
  Serial.println("[boot] hunting OLED on safe GPIO pairs..."); Serial.flush();
  uint8_t fSda = 0, fScl = 0;
  for (int i = 0; i < NCAND && !oledOK; i++) {
    for (int j = 0; j < NCAND && !oledOK; j++) {
      if (i == j) continue;
      uint8_t s = I2C_CAND[i], c = I2C_CAND[j];
      Wire.begin(s, c); Wire.setTimeOut(10);
      const uint8_t addrs[2] = {0x3C, 0x3D};
      for (int k = 0; k < 2; k++) {
        Wire.beginTransmission(addrs[k]);
        if (Wire.endTransmission() == 0) { oledOK = true; oledAddr = addrs[k]; fSda = s; fScl = c; break; }
      }
      Wire.end();
    }
  }

  if (oledOK) {
    Serial.printf("[boot] OLED FOUND -> SDA=%d SCL=%d addr=0x%02X\n", fSda, fScl, oledAddr); Serial.flush();
    u8x8_SetPin(u8g2.getU8x8(), U8X8_PIN_I2C_DATA,  fSda);   // runtime SW-I2C pin override
    u8x8_SetPin(u8g2.getU8x8(), U8X8_PIN_I2C_CLOCK, fScl);
    u8g2.setI2CAddress(oledAddr << 1);
    u8g2.begin();
    Serial.println("[boot] u8g2 ok"); Serial.flush();
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tf);
    u8g2.drawStr(2, 12, "THREAT RADAR C5");
    u8g2.setFont(u8g2_font_5x7_tf);
    u8g2.drawStr(2, 30, "dual-band 2.4 + 5GHz");
    u8g2.drawStr(2, 46, "init ble...");
    u8g2.sendBuffer();
  } else {
    Serial.println("[boot] OLED absent -> HEADLESS (serial logs only)"); Serial.flush();
  }

  // BLE (bundled Bluedroid) init FIRST -> before WiFi promiscuous (coexist safety)
  Serial.println("[boot] init ble..."); Serial.flush();
  BLEDevice::init("");
  pScan = BLEDevice::getScan();
  pScan->setAdvertisedDeviceCallbacks(new BLECB(), true /*wantDuplicates*/);
  pScan->setActiveScan(false);
  pScan->setInterval(100); pScan->setWindow(99);
  delay(50);
  Serial.println("[boot] ble ok"); Serial.flush();
  if (oledOK) { u8g2.drawStr(2, 56, "init wifi..."); u8g2.sendBuffer(); }

  // WiFi: STA starts the driver; disconnect(FALSE) keeps the radio ON
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(false);
  delay(150);

  // THE 5GHz KEY: AUTO band mode unlocks 5GHz channels for set_channel()
  esp_err_t eb = esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO);
  Serial.printf("[boot] band_mode AUTO: %s\n", esp_err_to_name(eb)); Serial.flush();

  esp_wifi_set_ps(WIFI_PS_NONE);
  esp_err_t e1 = esp_wifi_set_promiscuous(true);
  wifi_promiscuous_filter_t f; f.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&f);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
  hopIdx = 0;
  esp_err_t e2 = esp_wifi_set_channel(HOPS[0].ch, WIFI_SECOND_CHAN_NONE);
  Serial.printf("[boot] wifi: promisc=%s  ch%d=%s\n", esp_err_to_name(e1), HOPS[0].ch, esp_err_to_name(e2));

  memset(srcs,0,sizeof(srcs));
  phaseStart=millis(); lastHop=millis();
  Serial.println("[boot] radar up (detection only)"); Serial.flush();
}

void loop() {
  uint32_t now = millis();

  if (phase == PH_WIFI) {
    if (now - lastHop > 800) {
      lastHop = now; hopIdx = (hopIdx+1) % NHOP; hopTo(hopIdx);
    }
    const Hop &h = HOPS[hopIdx];
    if (h.txOk && now - lastBeacon > 800) {            // beacon on 2.4GHz only
      lastBeacon = now; beacon[BEACON_CHAN_IDX] = h.ch;
      for (int k=0;k<3;k++){ esp_wifi_80211_tx(WIFI_IF_STA, beacon, sizeof(beacon), true); delay(2); }
    }
    drainRing(now);
    if (now - phaseStart > 19000) {                    // full dual-band sweep done -> BLE
      wifiPromiscOn(false); delay(20);
      phase = PH_BLE; phaseStart = now;
      if (oledOK) drawNormal("BLE", HOPS[hopIdx]);     // show before the blocking scan
    }
  } else { // PH_BLE
    g_bleAdv=0; g_bleSpamCID=0;
    BLEScanResults *res = pScan->start(2, false);      // blocking ~2s
    bleUnique = res ? res->getCount() : 0;
    bleAdvLast = g_bleAdv;
    bleSpam = (bleAdvLast > 80) || (g_bleSpamCID > 40);
    pScan->clearResults(); pScan->stop();              // clearResults MANDATORY (heap)
    if (bleSpam) { alertActive=true; alertUntil=millis()+5000; strcpy(alertProto,"BLE SPAM");
      memset(alertMac,0,6); memset(alertVic,0,6); alertCh=0; alertRssi=0; }
    wifiPromiscOn(true); hopTo(hopIdx);
    phase = PH_WIFI; phaseStart = millis(); lastHop = millis();
  }

  // pwnagotchi presence -> soft alert
  if (now - g_pwnLastMs < 6000 && g_pwnCount>0 && !alertActive) {
    alertActive=true; alertUntil=now+5000; strcpy(alertProto,"PWNAGOTCHI");
    memcpy(alertMac,(const void*)g_pwnMac,6); memset(alertVic,0,6); alertRssi=g_pwnRssi; alertCh=0;
  }
  if (alertActive && now>alertUntil && activeAttackers()==0 && !bleSpam &&
      !(now-g_pwnLastMs<6000 && g_pwnCount>0)) alertActive=false;

  if (oledOK && now - lastDraw > 350) {
    lastDraw = now;
    if (alertActive) drawAlert();
    else drawNormal(phase==PH_WIFI?"WIFI":"BLE", HOPS[hopIdx]);
  }

  // continuous serial heartbeat (so logs show even if you connect after boot)
  if (now - lastLog > 3000) {
    lastLog = now;
    const Hop &h = HOPS[hopIdx];
    Serial.printf("[run] %s ch%d %s | rx=%lu 5g=%lu | atk=%d src=%d | pwn=%lu(%ddBm) | ble=%lu%s | heap=%lu\n",
      phase==PH_WIFI?"WIFI":"BLE", h.ch, h.band5?"5G":"2.4",
      (unsigned long)g_mgmtSeen, (unsigned long)g_rx5g,
      activeAttackers(), seenSources(),
      (unsigned long)g_pwnCount, g_pwnRssi,
      (unsigned long)bleUnique, bleSpam?" SPAM":"",
      (unsigned long)ESP.getFreeHeap());
  }

  if (ESP.getFreeHeap() < 28000) { Serial.println("low heap -> restart"); delay(50); ESP.restart(); }
}
