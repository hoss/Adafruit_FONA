/***************************************************
  This is a library for our Adafruit FONA Cellular Module

  Designed specifically to work with the Adafruit FONA
  ----> http://www.adafruit.com/products/1946
  ----> http://www.adafruit.com/products/1963

  These displays use TTL Serial to communicate, 2 pins are required to
  interface
  Adafruit invests time and resources providing this open source code,
  please support Adafruit and open-source hardware by purchasing
  products from Adafruit!

  Written by Limor Fried/Ladyada for Adafruit Industries.
  BSD license, all text above must be included in any redistribution
 ****************************************************/
// next line per http://postwarrior.com/arduino-ethershield-error-prog_char-does-not-name-a-type/

#include "Adafruit_FONA.h"

Adafruit_FONA::Adafruit_FONA(int8_t rst)
{
  _rstpin = rst;

  apn = F("FONAnet");
  apnusername = 0;
  apnpassword = 0;
  mySerial = 0;
  httpsredirect = false;
  useragent = F("FONA");
  ok_reply = F("OK");
}

uint8_t Adafruit_FONA::type(void)
{
  return _type;
}

boolean Adafruit_FONA::begin(Stream &port)
{
  mySerial = &port;

  pinMode(_rstpin, OUTPUT);
  digitalWrite(_rstpin, HIGH);
  delay(10);
  digitalWrite(_rstpin, LOW);
  delay(100);
  digitalWrite(_rstpin, HIGH);

  DEBUG_PRINTLN(F("Attempting to open comm with ATs"));
  // give 7 seconds to reboot
  int16_t timeout = 7000;

  while (timeout > 0)
  {
    while (mySerial->available())
      mySerial->read();
    if (sendCheckReply(F("AT"), ok_reply))
      break;
    while (mySerial->available())
      mySerial->read();
    if (sendCheckReply(F("AT"), F("AT")))
      break;
    delay(500);
    timeout -= 500;
  }

  if (timeout <= 0)
  {
#ifdef ADAFRUIT_FONA_DEBUG
    DEBUG_PRINTLN(F("Timeout: No response to AT... last ditch attempt."));
#endif
    sendCheckReply(F("AT"), ok_reply);
    delay(100);
    sendCheckReply(F("AT"), ok_reply);
    delay(100);
    sendCheckReply(F("AT"), ok_reply);
    delay(100);
  }

  // turn off Echo!
  sendCheckReply(F("ATE0"), ok_reply);
  delay(100);

  if (!sendCheckReply(F("ATE0"), ok_reply))
  {
    return false;
  }

  // turn on hangupitude
  sendCheckReply(F("AT+CVHU=0"), ok_reply);

  delay(100);
  flushInput();

  DEBUG_PRINT(F("\t---> "));
  DEBUG_PRINTLN("ATI");

  mySerial->println("ATI");
  readline(500, true);

  DEBUG_PRINT(F("\t<--- "));
  DEBUG_PRINTLN(replybuffer);

  if (prog_char_strstr(replybuffer, (prog_char *)F("SIM808 R14")) != 0)
  {
    _type = FONA808_V2;
  }
  else if (prog_char_strstr(replybuffer, (prog_char *)F("SIM808 R13")) != 0)
  {
    _type = FONA808_V1;
  }
  else if (prog_char_strstr(replybuffer, (prog_char *)F("SIM800 R13")) != 0)
  {
    _type = FONA800L;
  }
  else if (prog_char_strstr(replybuffer, (prog_char *)F("SIMCOM_SIM5320A")) != 0)
  {
    _type = FONA3G_A;
  }
  else if (prog_char_strstr(replybuffer, (prog_char *)F("SIMCOM_SIM5320E")) != 0)
  {
    _type = FONA3G_E;
  }

  if (_type == FONA800L)
  {
    // determine if L or H

    DEBUG_PRINT(F("\t---> "));
    DEBUG_PRINTLN("AT+GMM");

    mySerial->println("AT+GMM");
    readline(500, true);

    DEBUG_PRINT(F("\t<--- "));
    DEBUG_PRINTLN(replybuffer);

    if (prog_char_strstr(replybuffer, (prog_char *)F("SIM800H")) != 0)
    {
      _type = FONA800H;
    }
  }

#if defined(FONA_PREF_SMS_STORAGE)
  sendCheckReply(F("AT+CPMS=" FONA_PREF_SMS_STORAGE "," FONA_PREF_SMS_STORAGE "," FONA_PREF_SMS_STORAGE), ok_reply);
#endif

  return true;
}

/********* Serial port ********************************************/
boolean Adafruit_FONA::setBaudrate(uint16_t baud)
{
  return sendCheckReply(F("AT+IPREX="), baud, ok_reply);
}

/********* Real Time Clock ********************************************/

boolean Adafruit_FONA::readRTC(uint8_t *year, uint8_t *month, uint8_t *date, uint8_t *hr, uint8_t *min, uint8_t *sec)
{
  uint16_t v;
  sendParseReply(F("AT+CCLK?"), F("+CCLK: "), &v, '/', 0);
  *year = v;

  DEBUG_PRINTLN(*year);
}

boolean Adafruit_FONA::enableRTC(uint8_t i)
{
  if (!sendCheckReply(F("AT+CLTS="), i, ok_reply))
    return false;
  return sendCheckReply(F("AT&W"), ok_reply);
}

/********* BATTERY & ADC ********************************************/

/* returns value in mV (uint16_t) */
boolean Adafruit_FONA::getBattVoltage(uint16_t *v)
{
  return sendParseReply(F("AT+CBC"), F("+CBC: "), v, ',', 2);
}

/* returns the percentage charge of battery as reported by sim800 */
boolean Adafruit_FONA::getBattPercent(uint16_t *p)
{
  return sendParseReply(F("AT+CBC"), F("+CBC: "), p, ',', 1);
}

boolean Adafruit_FONA::getADCVoltage(uint16_t *v)
{
  return sendParseReply(F("AT+CADC?"), F("+CADC: 1,"), v);
}

/********* SIM ***********************************************************/

uint8_t Adafruit_FONA::unlockSIM(char *pin)
{
  char sendbuff[14] = "AT+CPIN=";
  sendbuff[8] = pin[0];
  sendbuff[9] = pin[1];
  sendbuff[10] = pin[2];
  sendbuff[11] = pin[3];
  sendbuff[12] = '\0';

  return sendCheckReply(sendbuff, ok_reply);
}

uint8_t Adafruit_FONA::getSIMCCID(char *ccid)
{
  getReply(F("AT+CCID"));
  // up to 28 chars for reply, 20 char total ccid
  if (replybuffer[0] == '+')
  {
    // fona 3g?
    strncpy(ccid, replybuffer + 8, 20);
  }
  else
  {
    // fona 800 or 800
    strncpy(ccid, replybuffer, 20);
  }
  ccid[20] = 0;

  readline(); // eat 'OK'

  return strlen(ccid);
}

/********* IMEI **********************************************************/

uint8_t Adafruit_FONA::getIMEI(char *imei)
{
  getReply(F("AT+GSN"));

  // up to 15 chars
  strncpy(imei, replybuffer, 15);
  imei[15] = 0;

  readline(); // eat 'OK'

  return strlen(imei);
}

/********* NETWORK *******************************************************/

uint8_t Adafruit_FONA::getNetworkStatus(void)
{
  uint16_t status;

  if (!sendParseReply(F("AT+CREG?"), F("+CREG: "), &status, ',', 1))
    return 0;

  return status;
}

uint8_t Adafruit_FONA::getRSSI(void)
{
  uint16_t reply;

  if (!sendParseReply(F("AT+CSQ"), F("+CSQ: "), &reply))
    return 0;

  return reply;
}

/********* AUDIO *******************************************************/

boolean Adafruit_FONA::setAudio(uint8_t a)
{
  // 0 is headset, 1 is external audio
  if (a > 1)
    return false;

  return sendCheckReply(F("AT+CHFA="), a, ok_reply);
}

uint8_t Adafruit_FONA::getVolume(void)
{
  uint16_t reply;

  if (!sendParseReply(F("AT+CLVL?"), F("+CLVL: "), &reply))
    return 0;

  return reply;
}

boolean Adafruit_FONA::setVolume(uint8_t i)
{
  return sendCheckReply(F("AT+CLVL="), i, ok_reply);
}

boolean Adafruit_FONA::playDTMF(char dtmf)
{
  char str[4];
  str[0] = '\"';
  str[1] = dtmf;
  str[2] = '\"';
  str[3] = 0;
  return sendCheckReply(F("AT+CLDTMF=3,"), str, ok_reply);
}

boolean Adafruit_FONA::playToolkitTone(uint8_t t, uint16_t len)
{
  return sendCheckReply(F("AT+STTONE=1,"), t, len, ok_reply);
}

boolean Adafruit_FONA::setMicVolume(uint8_t a, uint8_t level)
{
  // 0 is headset, 1 is external audio
  if (a > 1)
    return false;

  return sendCheckReply(F("AT+CMIC="), a, level, ok_reply);
}


/********* USSD *********************************************************/

boolean Adafruit_FONA::sendUSSD(char *ussdmsg, char *ussdbuff, uint16_t maxlen, uint16_t *readlen)
{
  if (!sendCheckReply(F("AT+CUSD=1"), ok_reply))
    return false;

  char sendcmd[30] = "AT+CUSD=1,\"";
  strncpy(sendcmd + 11, ussdmsg, 30 - 11 - 2); // 11 bytes beginning, 2 bytes for close quote + null
  sendcmd[strlen(sendcmd)] = '\"';

  if (!sendCheckReply(sendcmd, ok_reply))
  {
    *readlen = 0;
    return false;
  }
  else
  {
    readline(10000); // read the +CUSD reply, wait up to 10 seconds!!!
    //DEBUG_PRINT("* "); DEBUG_PRINTLN(replybuffer);
    char *p = prog_char_strstr(replybuffer, PSTR("+CUSD: "));
    if (p == 0)
    {
      *readlen = 0;
      return false;
    }
    p += 7; //+CUSD
    // Find " to get start of ussd message.
    p = strchr(p, '\"');
    if (p == 0)
    {
      *readlen = 0;
      return false;
    }
    p += 1; //"
    // Find " to get end of ussd message.
    char *strend = strchr(p, '\"');

    uint16_t lentocopy = min(maxlen - 1, strend - p);
    strncpy(ussdbuff, p, lentocopy + 1);
    ussdbuff[lentocopy] = 0;
    *readlen = lentocopy;
  }
  return true;
}

/********* TIME **********************************************************/

boolean Adafruit_FONA::enableNetworkTimeSync(boolean onoff)
{
  if (onoff)
  {
    if (!sendCheckReply(F("AT+CLTS=1"), ok_reply))
      return false;
  }
  else
  {
    if (!sendCheckReply(F("AT+CLTS=0"), ok_reply))
      return false;
  }

  flushInput(); // eat any 'Unsolicted Result Code'

  return true;
}

boolean Adafruit_FONA::enableNTPTimeSync(boolean onoff, FONAFlashStringPtr ntpserver)
{
  if (onoff)
  {
    if (!sendCheckReply(F("AT+CNTPCID=1"), ok_reply))
      return false;

    mySerial->print(F("AT+CNTP=\""));
    if (ntpserver != 0)
    {
      mySerial->print(ntpserver);
    }
    else
    {
      mySerial->print(F("pool.ntp.org"));
    }
    mySerial->println(F("\",0"));
    readline(FONA_DEFAULT_TIMEOUT_MS);
    if (strcmp(replybuffer, "OK") != 0)
      return false;

    if (!sendCheckReply(F("AT+CNTP"), ok_reply, 10000))
      return false;

    uint16_t status;
    readline(10000);
    if (!parseReply(F("+CNTP:"), &status))
      return false;
  }
  else
  {
    if (!sendCheckReply(F("AT+CNTPCID=0"), ok_reply))
      return false;
  }

  return true;
}

boolean Adafruit_FONA::getTime(char *buff, uint16_t maxlen)
{
  getReply(F("AT+CCLK?"), (uint16_t)10000);
  if (strncmp(replybuffer, "+CCLK: ", 7) != 0)
    return false;

  char *p = replybuffer + 7;
  uint16_t lentocopy = min(maxlen - 1, strlen(p));
  strncpy(buff, p, lentocopy + 1);
  buff[lentocopy] = 0;

  readline(); // eat OK

  return true;
}

/********* GPRS **********************************************************/

boolean Adafruit_FONA::enableGPRS(boolean onoff)
{

  if (onoff)
  {
    // disconnect all sockets
    sendCheckReply(F("AT+CIPSHUT"), F("SHUT OK"), 20000);

    if (!sendCheckReply(F("AT+CGATT=1"), ok_reply, 10000))
      return false;

    // set bearer profile! connection type GPRS
    if (!sendCheckReply(F("AT+SAPBR=3,1,\"CONTYPE\",\"GPRS\""),
                        ok_reply, 10000))
      return false;

    // set bearer profile access point name
    if (apn)
    {
      // Send command AT+SAPBR=3,1,"APN","<apn value>" where <apn value> is the configured APN value.
      if (!sendCheckReplyQuoted(F("AT+SAPBR=3,1,\"APN\","), apn, ok_reply, 10000))
        return false;

      // send AT+CSTT,"apn","user","pass"
      flushInput();

      mySerial->print(F("AT+CSTT=\""));
      mySerial->print(apn);
      if (apnusername)
      {
        mySerial->print("\",\"");
        mySerial->print(apnusername);
      }
      if (apnpassword)
      {
        mySerial->print("\",\"");
        mySerial->print(apnpassword);
      }
      mySerial->println("\"");

      DEBUG_PRINT(F("\t---> "));
      DEBUG_PRINT(F("AT+CSTT=\""));
      DEBUG_PRINT(apn);

      if (apnusername)
      {
        DEBUG_PRINT("\",\"");
        DEBUG_PRINT(apnusername);
      }
      if (apnpassword)
      {
        DEBUG_PRINT("\",\"");
        DEBUG_PRINT(apnpassword);
      }
      DEBUG_PRINTLN("\"");

      if (!expectReply(ok_reply))
        return false;

      // set username/password
      if (apnusername)
      {
        // Send command AT+SAPBR=3,1,"USER","<user>" where <user> is the configured APN username.
        if (!sendCheckReplyQuoted(F("AT+SAPBR=3,1,\"USER\","), apnusername, ok_reply, 10000))
          return false;
      }
      if (apnpassword)
      {
        // Send command AT+SAPBR=3,1,"PWD","<password>" where <password> is the configured APN password.
        if (!sendCheckReplyQuoted(F("AT+SAPBR=3,1,\"PWD\","), apnpassword, ok_reply, 10000))
          return false;
      }
    }

    // open GPRS context
    if (!sendCheckReply(F("AT+SAPBR=1,1"), ok_reply, 30000))
      return false;

    // bring up wireless connection
    if (!sendCheckReply(F("AT+CIICR"), ok_reply, 10000))
      return false;
  }
  else
  {
    // disconnect all sockets
    if (!sendCheckReply(F("AT+CIPSHUT"), F("SHUT OK"), 20000))
      return false;

    // close GPRS context
    if (!sendCheckReply(F("AT+SAPBR=0,1"), ok_reply, 10000))
      return false;

    if (!sendCheckReply(F("AT+CGATT=0"), ok_reply, 10000))
      return false;
  }
  return true;
}

uint8_t Adafruit_FONA::GPRSstate(void)
{
  uint16_t state;

  if (!sendParseReply(F("AT+CGATT?"), F("+CGATT: "), &state))
    return -1;

  return state;
}

void Adafruit_FONA::setGPRSNetworkSettings(FONAFlashStringPtr apn,
                                           FONAFlashStringPtr username, FONAFlashStringPtr password)
{
  this->apn = apn;
  this->apnusername = username;
  this->apnpassword = password;
}

boolean Adafruit_FONA::getGSMLoc(uint16_t *errorcode, char *buff, uint16_t maxlen)
{

  getReply(F("AT+CIPGSMLOC=1,1"), (uint16_t)10000);

  if (!parseReply(F("+CIPGSMLOC: "), errorcode))
    return false;

  char *p = replybuffer + 14;
  uint16_t lentocopy = min(maxlen - 1, strlen(p));
  strncpy(buff, p, lentocopy + 1);

  readline(); // eat OK

  return true;
}

boolean Adafruit_FONA::getGSMLoc(float *lat, float *lon)
{

  uint16_t returncode;
  char gpsbuffer[120];

  // make sure we could get a response
  if (!getGSMLoc(&returncode, gpsbuffer, 120))
    return false;

  // make sure we have a valid return code
  if (returncode != 0)
    return false;

  // +CIPGSMLOC: 0,-74.007729,40.730160,2015/10/15,19:24:55
  // tokenize the gps buffer to locate the lat & long
  char *longp = strtok(gpsbuffer, ",");
  if (!longp)
    return false;

  char *latp = strtok(NULL, ",");
  if (!latp)
    return false;

  *lat = atof(latp);
  *lon = atof(longp);

  return true;
}
/********* TCP FUNCTIONS  ************************************/

boolean Adafruit_FONA::TCPconnect(char *server, uint16_t port)
{
  flushInput();

  // close all old connections
  if (!sendCheckReply(F("AT+CIPSHUT"), F("SHUT OK"), 20000))
    return false;

  // single connection at a time
  if (!sendCheckReply(F("AT+CIPMUX=0"), ok_reply))
    return false;

  // manually read data
  if (!sendCheckReply(F("AT+CIPRXGET=1"), ok_reply))
    return false;

  DEBUG_PRINT(F("AT+CIPSTART=\"TCP\",\""));
  DEBUG_PRINT(server);
  DEBUG_PRINT(F("\",\""));
  DEBUG_PRINT(port);
  DEBUG_PRINTLN(F("\""));

  mySerial->print(F("AT+CIPSTART=\"TCP\",\""));
  mySerial->print(server);
  mySerial->print(F("\",\""));
  mySerial->print(port);
  mySerial->println(F("\""));

  if (!expectReply(ok_reply))
    return false;
  if (!expectReply(F("CONNECT OK")))
    return false;

  // looks like it was a success (?)
  return true;
}

boolean Adafruit_FONA::TCPclose(void)
{
  return sendCheckReply(F("AT+CIPCLOSE"), ok_reply);
}

boolean Adafruit_FONA::TCPconnected(void)
{
  if (!sendCheckReply(F("AT+CIPSTATUS"), ok_reply, 100))
    return false;
  readline(100);

  DEBUG_PRINT(F("\t<--- "));
  DEBUG_PRINTLN(replybuffer);

  return (strcmp(replybuffer, "STATE: CONNECT OK") == 0);
}

boolean Adafruit_FONA::TCPsend(char *packet, uint8_t len)
{

  DEBUG_PRINT(F("AT+CIPSEND="));
  DEBUG_PRINTLN(len);
#ifdef ADAFRUIT_FONA_DEBUG
  for (uint16_t i = 0; i < len; i++)
  {
    DEBUG_PRINT(F(" 0x"));
    DEBUG_PRINT(packet[i], HEX);
  }
#endif
  DEBUG_PRINTLN();

  mySerial->print(F("AT+CIPSEND="));
  mySerial->println(len);
  readline();

  DEBUG_PRINT(F("\t<--- "));
  DEBUG_PRINTLN(replybuffer);

  if (replybuffer[0] != '>')
    return false;

  mySerial->write(packet, len);
  readline(3000); // wait up to 3 seconds to send the data

  DEBUG_PRINT(F("\t<--- "));
  DEBUG_PRINTLN(replybuffer);

  return (strcmp(replybuffer, "SEND OK") == 0);
}

uint16_t Adafruit_FONA::TCPavailable(void)
{
  uint16_t avail;

  if (!sendParseReply(F("AT+CIPRXGET=4"), F("+CIPRXGET: 4,"), &avail, ',', 0))
    return false;

  DEBUG_PRINT(avail);
  DEBUG_PRINTLN(F(" bytes available"));

  return avail;
}

uint16_t Adafruit_FONA::TCPread(uint8_t *buff, uint8_t len)
{
  uint16_t avail;

  mySerial->print(F("AT+CIPRXGET=2,"));
  mySerial->println(len);
  readline();
  if (!parseReply(F("+CIPRXGET: 2,"), &avail, ',', 0))
    return false;

  readRaw(avail);

#ifdef ADAFRUIT_FONA_DEBUG
  DEBUG_PRINT(avail);
  DEBUG_PRINTLN(F(" bytes read"));
  for (uint8_t i = 0; i < avail; i++)
  {
    DEBUG_PRINT(F(" 0x"));
    DEBUG_PRINT(replybuffer[i], HEX);
  }
  DEBUG_PRINTLN();
#endif

  memcpy(buff, replybuffer, avail);

  return avail;
}

/********* HTTP LOW LEVEL FUNCTIONS  ************************************/

boolean Adafruit_FONA::HTTP_init()
{
  return sendCheckReply(F("AT+HTTPINIT"), ok_reply);
}

boolean Adafruit_FONA::HTTP_term()
{
  return sendCheckReply(F("AT+HTTPTERM"), ok_reply);
}

void Adafruit_FONA::HTTP_para_start(FONAFlashStringPtr parameter,
                                    boolean quoted)
{
  flushInput();

  DEBUG_PRINT(F("\t---> "));
  DEBUG_PRINT(F("AT+HTTPPARA=\""));
  DEBUG_PRINT(parameter);
  DEBUG_PRINTLN('"');

  mySerial->print(F("AT+HTTPPARA=\""));
  mySerial->print(parameter);
  if (quoted)
    mySerial->print(F("\",\""));
  else
    mySerial->print(F("\","));
}

boolean Adafruit_FONA::HTTP_para_end(boolean quoted)
{
  if (quoted)
    mySerial->println('"');
  else
    mySerial->println();

  return expectReply(ok_reply);
}

boolean Adafruit_FONA::HTTP_para(FONAFlashStringPtr parameter,
                                 const char *value)
{
  HTTP_para_start(parameter, true);
  mySerial->print(value);
  return HTTP_para_end(true);
}

boolean Adafruit_FONA::HTTP_para(FONAFlashStringPtr parameter,
                                 FONAFlashStringPtr value)
{
  HTTP_para_start(parameter, true);
  mySerial->print(value);
  return HTTP_para_end(true);
}

boolean Adafruit_FONA::HTTP_para(FONAFlashStringPtr parameter,
                                 int32_t value)
{
  HTTP_para_start(parameter, false);
  mySerial->print(value);
  return HTTP_para_end(false);
}

boolean Adafruit_FONA::HTTP_data(uint32_t size, uint32_t maxTime)
{
  flushInput();

  DEBUG_PRINT(F("\t---> "));
  DEBUG_PRINT(F("AT+HTTPDATA="));
  DEBUG_PRINT(size);
  DEBUG_PRINT(',');
  DEBUG_PRINTLN(maxTime);

  mySerial->print(F("AT+HTTPDATA="));
  mySerial->print(size);
  mySerial->print(",");
  mySerial->println(maxTime);

  return expectReply(F("DOWNLOAD"));
}

boolean Adafruit_FONA::HTTP_action(uint8_t method, uint16_t *status,
                                   uint16_t *datalen, int32_t timeout)
{
  // Send request.
  if (!sendCheckReply(F("AT+HTTPACTION="), method, ok_reply))
    return false;

  // Parse response status and size.
  readline(timeout);
  if (!parseReply(F("+HTTPACTION:"), status, ',', 1))
    return false;
  if (!parseReply(F("+HTTPACTION:"), datalen, ',', 2))
    return false;

  return true;
}

boolean Adafruit_FONA::HTTP_readall(uint16_t *datalen)
{
  getReply(F("AT+HTTPREAD"));
  if (!parseReply(F("+HTTPREAD:"), datalen, ',', 0))
    return false;

  return true;
}

boolean Adafruit_FONA::HTTP_ssl(boolean onoff)
{
  return sendCheckReply(F("AT+HTTPSSL="), onoff ? 1 : 0, ok_reply);
}

/********* HTTP HIGH LEVEL FUNCTIONS ***************************/

boolean Adafruit_FONA::HTTP_GET_start(char *url,
                                      uint16_t *status, uint16_t *datalen)
{
  if (!HTTP_setup(url))
    return false;

  // HTTP GET
  if (!HTTP_action(FONA_HTTP_GET, status, datalen, 30000))
    return false;

  DEBUG_PRINT(F("Status: "));
  DEBUG_PRINTLN(*status);
  DEBUG_PRINT(F("Len: "));
  DEBUG_PRINTLN(*datalen);

  // HTTP response data
  if (!HTTP_readall(datalen))
    return false;

  return true;
}
void Adafruit_FONA::HTTP_GET_end(void)
{
  HTTP_term();
}

boolean Adafruit_FONA::HTTP_POST_start(char *url,
                                       FONAFlashStringPtr contenttype,
                                       const uint8_t *postdata, uint16_t postdatalen,
                                       uint16_t *status, uint16_t *datalen)
{
  if (!HTTP_setup(url))
    return false;

  if (!HTTP_para(F("CONTENT"), contenttype))
  {
    return false;
  }

  // HTTP POST data
  if (!HTTP_data(postdatalen, 10000))
    return false;
  mySerial->write(postdata, postdatalen);
  if (!expectReply(ok_reply))
    return false;

  // HTTP POST
  if (!HTTP_action(FONA_HTTP_POST, status, datalen))
    return false;

  DEBUG_PRINT(F("Status: "));
  DEBUG_PRINTLN(*status);
  DEBUG_PRINT(F("Len: "));
  DEBUG_PRINTLN(*datalen);

  // HTTP response data
  if (!HTTP_readall(datalen))
    return false;

  return true;
}

void Adafruit_FONA::HTTP_POST_end(void)
{
  HTTP_term();
}

void Adafruit_FONA::setUserAgent(FONAFlashStringPtr useragent)
{
  this->useragent = useragent;
}

void Adafruit_FONA::setHTTPSRedirect(boolean onoff)
{
  httpsredirect = onoff;
}

/********* HTTP HELPERS ****************************************/

boolean Adafruit_FONA::HTTP_setup(char *url)
{
  // Handle any pending
  HTTP_term();

  // Initialize and set parameters
  if (!HTTP_init())
    return false;
  if (!HTTP_para(F("CID"), 1))
    return false;
  if (!HTTP_para(F("UA"), useragent))
    return false;
  if (!HTTP_para(F("URL"), url))
    return false;

  // HTTPS redirect
  if (httpsredirect)
  {
    if (!HTTP_para(F("REDIR"), 1))
      return false;

    if (!HTTP_ssl(true))
      return false;
  }

  return true;
}

/********* HELPERS *********************************************/

boolean Adafruit_FONA::expectReply(FONAFlashStringPtr reply,
                                   uint16_t timeout)
{
  readline(timeout);

  DEBUG_PRINT(F("\t<--- "));
  DEBUG_PRINTLN(replybuffer);

  return (prog_char_strcmp(replybuffer, (prog_char *)reply) == 0);
}

/********* LOW LEVEL *******************************************/

inline int Adafruit_FONA::available(void)
{
  return mySerial->available();
}

inline size_t Adafruit_FONA::write(uint8_t x)
{
  return mySerial->write(x);
}

inline int Adafruit_FONA::read(void)
{
  return mySerial->read();
}

inline int Adafruit_FONA::peek(void)
{
  return mySerial->peek();
}

inline void Adafruit_FONA::flush()
{
  mySerial->flush();
}

void Adafruit_FONA::flushInput()
{
  // Read all available serial input to flush pending data.
  uint16_t timeoutloop = 0;
  while (timeoutloop++ < 40)
  {
    while (available())
    {
      read();
      timeoutloop = 0; // If char was received reset the timer
    }
    delay(1);
  }
}

uint16_t Adafruit_FONA::readRaw(uint16_t b)
{
  uint16_t idx = 0;

  while (b && (idx < sizeof(replybuffer) - 1))
  {
    if (mySerial->available())
    {
      replybuffer[idx] = mySerial->read();
      idx++;
      b--;
    }
  }
  replybuffer[idx] = 0;

  return idx;
}

uint8_t Adafruit_FONA::readline(uint16_t timeout, boolean multiline)
{
  uint16_t replyidx = 0;

  while (timeout--)
  {
    if (replyidx >= 254)
    {
      //DEBUG_PRINTLN(F("SPACE"));
      break;
    }

    while (mySerial->available())
    {
      char c = mySerial->read();
      if (c == '\r')
        continue;
      if (c == 0xA)
      {
        if (replyidx == 0) // the first 0x0A is ignored
          continue;

        if (!multiline)
        {
          timeout = 0; // the second 0x0A is the end of the line
          break;
        }
      }
      replybuffer[replyidx] = c;
      //DEBUG_PRINT(c, HEX); DEBUG_PRINT("#"); DEBUG_PRINTLN(c);
      replyidx++;
    }

    if (timeout == 0)
    {
      //DEBUG_PRINTLN(F("TIMEOUT"));
      break;
    }
    delay(1);
  }
  replybuffer[replyidx] = 0; // null term
  return replyidx;
}

uint8_t Adafruit_FONA::getReply(char *send, uint16_t timeout)
{
  flushInput();

  DEBUG_PRINT(F("\t---> "));
  DEBUG_PRINTLN(send);

  mySerial->println(send);

  uint8_t l = readline(timeout);

  DEBUG_PRINT(F("\t<--- "));
  DEBUG_PRINTLN(replybuffer);

  return l;
}

uint8_t Adafruit_FONA::getReply(FONAFlashStringPtr send, uint16_t timeout)
{
  flushInput();

  DEBUG_PRINT(F("\t---> "));
  DEBUG_PRINTLN(send);

  mySerial->println(send);

  uint8_t l = readline(timeout);

  DEBUG_PRINT(F("\t<--- "));
  DEBUG_PRINTLN(replybuffer);

  return l;
}

// Send prefix, suffix, and newline. Return response (and also set replybuffer with response).
uint8_t Adafruit_FONA::getReply(FONAFlashStringPtr prefix, char *suffix, uint16_t timeout)
{
  flushInput();

  DEBUG_PRINT(F("\t---> "));
  DEBUG_PRINT(prefix);
  DEBUG_PRINTLN(suffix);

  mySerial->print(prefix);
  mySerial->println(suffix);

  uint8_t l = readline(timeout);

  DEBUG_PRINT(F("\t<--- "));
  DEBUG_PRINTLN(replybuffer);

  return l;
}

// Send prefix, suffix, and newline. Return response (and also set replybuffer with response).
uint8_t Adafruit_FONA::getReply(FONAFlashStringPtr prefix, int32_t suffix, uint16_t timeout)
{
  flushInput();

  DEBUG_PRINT(F("\t---> "));
  DEBUG_PRINT(prefix);
  DEBUG_PRINTLN(suffix, DEC);

  mySerial->print(prefix);
  mySerial->println(suffix, DEC);

  uint8_t l = readline(timeout);

  DEBUG_PRINT(F("\t<--- "));
  DEBUG_PRINTLN(replybuffer);

  return l;
}

// Send prefix, suffix, suffix2, and newline. Return response (and also set replybuffer with response).
uint8_t Adafruit_FONA::getReply(FONAFlashStringPtr prefix, int32_t suffix1, int32_t suffix2, uint16_t timeout)
{
  flushInput();

  DEBUG_PRINT(F("\t---> "));
  DEBUG_PRINT(prefix);
  DEBUG_PRINT(suffix1, DEC);
  DEBUG_PRINT(',');
  DEBUG_PRINTLN(suffix2, DEC);

  mySerial->print(prefix);
  mySerial->print(suffix1);
  mySerial->print(',');
  mySerial->println(suffix2, DEC);

  uint8_t l = readline(timeout);

  DEBUG_PRINT(F("\t<--- "));
  DEBUG_PRINTLN(replybuffer);

  return l;
}

// Send prefix, ", suffix, ", and newline. Return response (and also set replybuffer with response).
uint8_t Adafruit_FONA::getReplyQuoted(FONAFlashStringPtr prefix, FONAFlashStringPtr suffix, uint16_t timeout)
{
  flushInput();

  DEBUG_PRINT(F("\t---> "));
  DEBUG_PRINT(prefix);
  DEBUG_PRINT('"');
  DEBUG_PRINT(suffix);
  DEBUG_PRINTLN('"');

  mySerial->print(prefix);
  mySerial->print('"');
  mySerial->print(suffix);
  mySerial->println('"');

  uint8_t l = readline(timeout);

  DEBUG_PRINT(F("\t<--- "));
  DEBUG_PRINTLN(replybuffer);

  return l;
}

boolean Adafruit_FONA::sendCheckReply(char *send, char *reply, uint16_t timeout)
{
  if (!getReply(send, timeout))
    return false;
  /*
  for (uint8_t i=0; i<strlen(replybuffer); i++) {
  DEBUG_PRINT(replybuffer[i], HEX); DEBUG_PRINT(" ");
  }
  DEBUG_PRINTLN();
  for (uint8_t i=0; i<strlen(reply); i++) {
    DEBUG_PRINT(reply[i], HEX); DEBUG_PRINT(" ");
  }
  DEBUG_PRINTLN();
  */
  return (strcmp(replybuffer, reply) == 0);
}

boolean Adafruit_FONA::sendCheckReply(FONAFlashStringPtr send, FONAFlashStringPtr reply, uint16_t timeout)
{
  if (!getReply(send, timeout))
    return false;

  return (prog_char_strcmp(replybuffer, (prog_char *)reply) == 0);
}

boolean Adafruit_FONA::sendCheckReply(char *send, FONAFlashStringPtr reply, uint16_t timeout)
{
  if (!getReply(send, timeout))
    return false;
  return (prog_char_strcmp(replybuffer, (prog_char *)reply) == 0);
}

// Send prefix, suffix, and newline.  Verify FONA response matches reply parameter.
boolean Adafruit_FONA::sendCheckReply(FONAFlashStringPtr prefix, char *suffix, FONAFlashStringPtr reply, uint16_t timeout)
{
  getReply(prefix, suffix, timeout);
  return (prog_char_strcmp(replybuffer, (prog_char *)reply) == 0);
}

// Send prefix, suffix, and newline.  Verify FONA response matches reply parameter.
boolean Adafruit_FONA::sendCheckReply(FONAFlashStringPtr prefix, int32_t suffix, FONAFlashStringPtr reply, uint16_t timeout)
{
  getReply(prefix, suffix, timeout);
  return (prog_char_strcmp(replybuffer, (prog_char *)reply) == 0);
}

// Send prefix, suffix, suffix2, and newline.  Verify FONA response matches reply parameter.
boolean Adafruit_FONA::sendCheckReply(FONAFlashStringPtr prefix, int32_t suffix1, int32_t suffix2, FONAFlashStringPtr reply, uint16_t timeout)
{
  getReply(prefix, suffix1, suffix2, timeout);
  return (prog_char_strcmp(replybuffer, (prog_char *)reply) == 0);
}

// Send prefix, ", suffix, ", and newline.  Verify FONA response matches reply parameter.
boolean Adafruit_FONA::sendCheckReplyQuoted(FONAFlashStringPtr prefix, FONAFlashStringPtr suffix, FONAFlashStringPtr reply, uint16_t timeout)
{
  getReplyQuoted(prefix, suffix, timeout);
  return (prog_char_strcmp(replybuffer, (prog_char *)reply) == 0);
}

boolean Adafruit_FONA::parseReply(FONAFlashStringPtr toreply,
                                  uint16_t *v, char divider, uint8_t index)
{
  char *p = prog_char_strstr(replybuffer, (prog_char *)toreply); // get the pointer to the voltage
  if (p == 0)
    return false;
  p += prog_char_strlen((prog_char *)toreply);
  //DEBUG_PRINTLN(p);
  for (uint8_t i = 0; i < index; i++)
  {
    // increment dividers
    p = strchr(p, divider);
    if (!p)
      return false;
    p++;
    //DEBUG_PRINTLN(p);
  }
  *v = atoi(p);

  return true;
}

boolean Adafruit_FONA::parseReply(FONAFlashStringPtr toreply,
                                  char *v, char divider, uint8_t index)
{
  uint8_t i = 0;
  char *p = prog_char_strstr(replybuffer, (prog_char *)toreply);
  if (p == 0)
    return false;
  p += prog_char_strlen((prog_char *)toreply);

  for (i = 0; i < index; i++)
  {
    // increment dividers
    p = strchr(p, divider);
    if (!p)
      return false;
    p++;
  }

  for (i = 0; i < strlen(p); i++)
  {
    if (p[i] == divider)
      break;
    v[i] = p[i];
  }

  v[i] = '\0';

  return true;
}

// Parse a quoted string in the response fields and copy its value (without quotes)
// to the specified character array (v).  Only up to maxlen characters are copied
// into the result buffer, so make sure to pass a large enough buffer to handle the
// response.
boolean Adafruit_FONA::parseReplyQuoted(FONAFlashStringPtr toreply,
                                        char *v, int maxlen, char divider, uint8_t index)
{
  uint8_t i = 0, j;
  // Verify response starts with toreply.
  char *p = prog_char_strstr(replybuffer, (prog_char *)toreply);
  if (p == 0)
    return false;
  p += prog_char_strlen((prog_char *)toreply);

  // Find location of desired response field.
  for (i = 0; i < index; i++)
  {
    // increment dividers
    p = strchr(p, divider);
    if (!p)
      return false;
    p++;
  }

  // Copy characters from response field into result string.
  for (i = 0, j = 0; j < maxlen && i < strlen(p); ++i)
  {
    // Stop if a divier is found.
    if (p[i] == divider)
      break;
    // Skip any quotation marks.
    else if (p[i] == '"')
      continue;
    v[j++] = p[i];
  }

  // Add a null terminator if result string buffer was not filled.
  if (j < maxlen)
    v[j] = '\0';

  return true;
}

boolean Adafruit_FONA::sendParseReply(FONAFlashStringPtr tosend,
                                      FONAFlashStringPtr toreply,
                                      uint16_t *v, char divider, uint8_t index)
{
  getReply(tosend);

  if (!parseReply(toreply, v, divider, index))
    return false;

  readline(); // eat 'OK'

  return true;
}


