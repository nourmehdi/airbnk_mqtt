from __future__ import annotations
import asyncio
import datetime
from homeassistant.helpers.config_validation import service
import time
import hashlib
from typing import Callable
from Cryptodome import Random
from Cryptodome.Cipher import AES
from base64 import b64encode, b64decode
import json


import voluptuous as vol
from voluptuous.schema_builder import Self

from homeassistant.components import mqtt
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.helpers.typing import ConfigType

# next section replace the part after cmnd with your tasmota device like  cmnd/your device/BLEOP1
BLEOpTopic = "cmnd/tasmota_DD5424/BLEOP1"
writecharacteristicuuid = "FFF2"
readcharacteristicuuid = "FFF3"
serviceuuid = "FFF0"
# THis is the Locker advertissing object will have properties advertised by the lock via BT or via tasmota mqtt as relevant
class AirbnkLockBleApi:

    utcMinutes = None
    voltage = None
    isBackLock = None
    isInit = None
    isImageA = None
    isHadNewRecord = None
    states = None
    softVersion = None
    isEnableAuto = None
    isLeftOpen = None
    isLowBattery = None
    magnetStates = None
    isMagnetEnable = None
    isBABA = None
    advscandata = None
    lversionOfSoft = None
    versionOfSoft = None
    versionCode = None
    serialnumber = None
    lockEvents = 0
    manufactureKey = "12345678901234567890"
    oldMainKey = "12345678901234567890"
    roomMainKey = "12345678901234567890"
    systemTime = 0
    roomEvents = 0
    guestEvents = 0
    macadress = ""
    devicename = ""
    test = ""
    lastmqttmsgpayload = ""
    islocking = False
    isunlocking = False
    lockinoperation = False
    frame1hex = ""
    frame2hex = ""
    trigger = 0
    frame1sent = False
    frame2sent = False
    time1 = 0
    isavailable = False

    def __init__(self, hass: HomeAssistant, bindingkey, manufacturerkey, macadress):
        self.manufactureKey = manufacturerkey
        self.oldMainKey = manufacturerkey
        self.roomMainKey = bindingkey
        self.macadress = macadress
        self.hass = hass
        self._callbacks = set()

    @property
    def islocked(self) -> bool | None:
        if self.states == 0:
            return True
        else:
            return False

    @property
    def isunlocked(self) -> bool | None:
        if self.states == 1:
            return True
        else:
            return False

    @property
    def isjammed(self) -> bool | None:
        if self.states == 2:
            return True
        else:
            return False

    @property
    def state(self):
        if self.states == 1:
            return "unlocked"
        elif self.states == 0:
            return "locked"
        elif self.states == 2:
            return "jammed"

    def register_callback(self, callback: Callable[[], None]) -> None:
        """Register callback, called when lock changes state."""
        print("register callback called")
        self._callbacks.add(callback)

    def parsefromfff3readprop(self, sn, barr=[0]):
        # Initialising empty Lockeradvertising variables
        # The init initialiser is used to init object from BLE read properties returned when reading
        # 0Xfff3 characteristic

        # According to type of the lock , checks the byte array and parse using type1 or type2 func

        if barr != [0] and barr != None:
            if (barr[6] & 255) == 240:
                self.type1(barr, sn)
            else:
                self.type2(barr, sn)

    def parsefromMQTTBLEHEXDETAILS(self, hexdata):
        # THis function will parse data received on mqtt from bledetails message
        if hexdata != None and hexdata != [0] and len(hexdata) == 62:
            newhexdata = hexdata[10:58]
            self.advscandata = newhexdata
            arraynewhexdata = bytearray.fromhex(newhexdata)
            if (arraynewhexdata[0] & 255) == 186 & (arraynewhexdata[1] & 255) == 186:
                self.parse3(arraynewhexdata)

    def dealwithmqttmsg(self, msg):
        payload = json.loads(msg)
        if "details" in payload:
            if "p" and "mac" in payload["details"]:
                if payload["details"]["mac"] == self.macadress:
                    self.lastmqttmsgpayload = payload["details"]["p"]
                    self.parsefromMQTTBLEHEXDETAILS(self.lastmqttmsgpayload)
                    self.time2 = self.time1
                    self.time1 = int(round(time.time()))

                    deltatime = self.time1 - self.time2
                    if deltatime < 30:
                        self.isavailable = True
                        print(str(deltatime))
                    elif deltatime > 30:
                        print(str(deltatime))
                        self.isavailable = False

                    for callback in self._callbacks:
                        callback()

        if "BLEOperation" in payload:
            if "state" and "MAC" in payload["BLEOperation"]:
                if (
                    payload["BLEOperation"]["state"] == "DONEWRITE"
                    and payload["BLEOperation"]["MAC"] == self.macadress
                    and payload["BLEOperation"]["write"] == self.frame1hex.upper()
                ):
                    self.frame1sent = True
                    print("calling sendframe2 now")
                    self.sendframe2()

        if "BLEOperation" in payload:
            if "state" and "MAC" in payload["BLEOperation"]:
                if (
                    payload["BLEOperation"]["state"] == "DONEWRITE"
                    and payload["BLEOperation"]["MAC"] == self.macadress
                    and payload["BLEOperation"]["write"] == self.frame2hex.upper()
                ):
                    self.frame2sent = True
                    self.lockinoperation = False
                    self.islocking = False
                    self.isunlocking = False
                    for callback in self._callbacks:
                        callback()

    async def lock(self):
        if self.islocked == True:
            return
        self.islocking = True
        for callback in self._callbacks:
            callback()
        self.frame1sent = False
        self.frame2sent = False
        if self.lockinoperation == False:
            barr = self.getCloseLockHexstring()
            lockprot1 = lockprot()
            lockprot1.beginDirective(barr)
            self.frame1hex = lockprot1.finalhex
            lockprot1.sendNextFrame()
            self.frame2hex = lockprot1.finalhex
            self.lockinoperation = True
            print(self.frame1hex)
            print(self.frame2hex)
            print(self.lockEvents)
            self.sendframe1()

    async def unlock(self):
        self.isunlocking = True
        self.frame1sent = False
        self.frame2sent = False
        if self.lockinoperation == False:
            barr = self.getOpenLockHexstring()
            lockprot1 = lockprot()
            lockprot1.beginDirective(barr)
            self.frame1hex = lockprot1.finalhex
            lockprot1.sendNextFrame()
            self.frame2hex = lockprot1.finalhex
            self.lockinoperation = True
            print(self.frame1hex)
            print(self.frame2hex)
            print(self.lockEvents)
            self.sendframe1()

    def sendframe1(self):
        mqtt.publish(self.hass, BLEOpTopic, self.BLEOPWritePAYLOADGen(self.frame1hex))

    def sendframe2(self):
        mqtt.publish(self.hass, BLEOpTopic, self.BLEOPWritePAYLOADGen(self.frame2hex))

    def BLEOPWritePAYLOADGen(self, frame):
        return f"M:{self.macadress} s:{serviceuuid} c:{writecharacteristicuuid} w:{frame} go"

    def BLEOPreadPAYLOADGen(self):
        return f"M:{self.macadress} s:{serviceuuid} c:{readcharacteristicuuid} r go"

    # The section below is the section related to the lock hex code generation algorithm(for opening and closing)

    def type1(self, barr, sn):
        self.serialnumber = sn
        self.lockEvents = (
            ((barr[10] & 255) << 24)
            | ((barr[11] & 255) << 16)
            | ((barr[12] & 255) << 8)
            | (barr[13] & 255)
        )
        self.voltage = ((((barr[14] & 255) << 8) | (barr[15] & 255))) * 0.01
        magnetenableindex = False
        self.isBackLock = (barr[16] & 1) != 0
        self.isInit = (barr[16] & 2) != 0
        self.isImageA = (barr[16] & 4) != 0
        self.isHadNewRecord = (barr[16] & 8) != 0
        i = ((barr[16] & 255) >> 4) & 7

        if i == 0 or i == 5:
            self.states = 1
        elif i == 1 or i == 4:
            self.states = 0
        else:
            self.states = 2

        self.softVersion = (
            (str(int(barr[7]))) + "." + (str(int(barr[8]))) + "." + (str(int(barr[9])))
        )
        self.isEnableAuto = (barr[16] & 128) != 0
        self.isLeftOpen = (barr[16] & 64) == 0
        self.isLowBattery = (16 & barr[17]) != 0
        self.magnetStates = (barr[17] >> 5) & 3
        if (barr[17] & 128) != 0:
            magnetenableindex = True

        self.isMagnetEnable = magnetenableindex
        self.isBABA = True
        self.advscandata = self.parse1(barr, sn)

    # Function used to set properties type2 lock
    def type2(self, barr, sn):
        self.serialnumber = sn
        self.lockEvents = (
            ((barr[8] & 255) << 24)
            | ((barr[9] & 255) << 16)
            | ((barr[10] & 255) << 8)
            | (barr[11] & 255)
        )
        self.utcMinutes = (
            ((barr[12] & 255) << 24)
            | ((barr[13] & 255) << 16)
            | ((barr[14] & 255) << 8)
            | (barr[15] & 255)
        )
        self.voltage = ((barr[16] & 255)) * 0.1
        index = True
        self.isBackLock = (barr[17] & 1) != 0
        self.isInit = (barr[17] & 2) != 0
        self.isImageA = (barr[17] & 4) != 0
        self.isHadNewRecord = (8 & barr[17]) != 0
        self.states = ((barr[17] & 255) >> 4) & 3
        self.isEnableAuto = (barr[17] & 64) != 0
        if (barr[17] & 128) == 0:
            index = False

        self.isLeftOpen = index
        self.isBABA = False
        self.advscandata = self.parse2(barr, sn)

    def parse2(self, barr, sn):
        if barr == None:
            return None

        barr2 = bytearray(23)
        barr2[0] = 173
        barr2[1] = barr[6]
        barr2[2] = barr[7]
        if sn != None and len(sn) > 0:
            length = len(sn)
            bytes1 = bytes(sn, "utf-8")
            for i in range(length):

                barr2[i + 3] = bytes1[i]

        barr2[12] = barr[8]
        barr2[13] = barr[9]
        barr2[14] = barr[10]
        barr2[15] = barr[11]
        barr2[16] = barr[12]
        barr2[17] = barr[13]
        barr2[18] = barr[14]
        barr2[19] = barr[15]
        barr2[20] = barr[16]
        barr2[21] = barr[17]
        barr2[22] = barr[18]

        return bytearray.hex(barr2)

    def parse1(self, barr, sn):
        if barr == None:
            return None

        barr2 = bytearray(24)
        barr2[0] = 186
        barr2[1] = 186
        barr2[4] = barr[7]
        barr2[5] = barr[8]
        barr2[6] = barr[9]
        if sn != None and len(sn) > 0:
            length = len(sn)
            bytes1 = bytes(sn, "utf-8")
            for i in range(length):
                barr2[i + 7] = bytes1[i]

        barr2[16] = barr[14]
        barr2[17] = barr[15]
        barr2[18] = barr[10]
        barr2[19] = barr[11]
        barr2[20] = barr[12]
        barr2[21] = barr[13]
        barr2[22] = barr[16]
        barr2[23] = barr[17]

        return bytearray.hex(barr2)

    def parse3(self, bArr):

        i = ((bArr[4] & 255) << 16) | ((bArr[5] & 255) << 8) | (bArr[6] & 255)
        self.voltage = ((float)(((bArr[16] & 255) << 8) | (bArr[17] & 255))) * 0.01
        self.boardModel = bArr[2] & 255
        self.lversionOfSoft = bArr[3] & 255
        self.sversionOfSoft = i
        self.serialnumber = self.Bytes2AsciiString(bArr, 7, 16)
        self.lockEvents = (
            ((bArr[18] & 255) << 24)
            | ((bArr[19] & 255) << 16)
            | ((bArr[20] & 255) << 8)
            | (bArr[21] & 255)
        )
        z = False
        self.isBackLock = (bArr[22] & 1) != 0
        self.isInit = (2 & bArr[22]) != 0
        self.isImageA = (bArr[22] & 4) != 0
        self.isHadNewRecord = (bArr[22] & 8) != 0
        self.states = ((bArr[22] & 255) >> 4) & 3
        self.isEnableAuto = (bArr[22] & 64) != 0
        self.isLeftOpen = (bArr[22] & 128) != 0
        self.isLowBattery = (bArr[23] & 16) != 0
        self.magnetStates = (bArr[23] >> 5) & 3
        if (bArr[23] & 128) != 0:
            z = True

        self.isMagnetEnable = z
        self.advData = bytearray.hex(bArr)
        self.isBABA = True

        return

    # the lockoperation function is used for open/close ops but also for managing the lock
    # and changing configuration(coming)
    def lockoperation(self, j):
        if j != 1 and j != 2:
            return None

        # info.serialNumber=sn

        self.systemTime = 1631553982
        # info.systemTime=int(round(time.time()))
        return self.PKV3(3, 3, j + 16)

    def getOpenLockHexstring(self):
        return self.lockoperation(1)

    def getCloseLockHexstring(self):
        return self.lockoperation(2)

    # Pakutil module section

    def Bytes2AsciiString(self, bArr, i, i2):

        bArr2 = bytearray(i2 - i)
        for i3 in range(i2 - i):
            bArr2[i3 - i + i] = bArr[i3 + i]

        return self.byteToString(bArr2)

    def byteToString(self, bArr):

        strr = ""
        for i in range(len(bArr)):
            strr = strr + chr(bArr[i])

        return strr

    def getCheckSum(self, bArr, i, i2):
        c = 0
        for i3 in range(i):

            c = c + bArr[i3 + i2]

        return c.to_bytes(4, "little")[0]

    def pwd2(self, barr):
        barr2 = bytearray(8)
        for i in range(4):
            b = barr[i + 16]
            i2 = i * 2
            barr2[i2] = barr[(b >> 4) & 15]
            barr2[i2 + 1] = barr[b & 15]

        return barr2

    def sig2(self, barr, i, star):

        lengthst = len(star)
        for r in range(lengthst):
            print("ord    " + str(ord(star[r])))
        barr2 = bytearray(len(star) + 68)
        for i2 in range(20):
            barr2[i2] = barr[i2]

        X64B36var = self.X64B36(barr2)
        print("X64B36var   " + X64B36var.hex())
        for i3 in range(lengthst):
            X64B36var[i3 + 64] = ord(star[i3])

        print("X64B36var afterloop   " + X64B36var.hex())
        i4 = lengthst + 64
        o = int(i) >> 24
        p = int(i) >> 16
        l = int(i) >> 8
        X64B36var[i4] = o.to_bytes(1, "little")[0]
        X64B36var[i4 + 1] = p.to_bytes(4, "little")[0]
        X64B36var[i4 + 2] = l.to_bytes(4, "little")[0]
        X64B36var[i4 + 3] = i.to_bytes(4, "little")[0]
        print("xor hex   " + X64B36var.hex())
        digest1 = self.digest(X64B36var)
        print("digest1   " + digest1.hex())

        barr3 = bytearray(84)
        for i5 in range(20):
            barr3[i5] = barr[i5]

        X64B5Cvar = self.X64B5C(barr3)
        print("X64B5Cvar   " + X64B5Cvar.hex())
        for i6 in range(len(digest1)):
            X64B5Cvar[i6 + 64] = digest1[i6]

        return self.pwd2(self.digest(X64B5Cvar))

    def X64B36(self, barr):

        for i in range(64):
            barr[i] = barr[i] ^ 54

        return barr

    def X64B5C(self, barr):
        for i in range(64):
            barr[i] = barr[i] ^ 92

        return barr

    def digest(self, barr):
        h = hashlib.sha1()
        h.update(barr)
        return h.digest()

    def WK(self, barr, i):

        barr2 = bytearray(72)
        for i2 in range(len(barr)):
            barr2[i2] = barr[i2]

        X64B36var = self.X64B36(barr2)

        o = i >> 24
        p = i >> 16
        l = i >> 8
        X64B36var[68] = o.to_bytes(1, "little")[0]
        X64B36var[69] = p.to_bytes(1, "little")[0]
        X64B36var[70] = l.to_bytes(1, "little")[0]
        X64B36var[71] = i.to_bytes(1, "little")[0]
        digestvar = self.digest(X64B36var)

        barr3 = bytearray(84)
        for i3 in range(len(barr)):
            barr3[i3] = barr[i3]

        X64B5Cvar = self.X64B5C(barr3)
        print(X64B5Cvar.hex())
        for i4 in range(len(digestvar)):
            X64B5Cvar[i4 + 64] = digestvar[i4]

        return self.digest(X64B5Cvar)

    def AESEncrypt(self, barr, key):
        if len(key) < 16 or key == None:
            return None
        if len(key) >= 16:
            key = key[0:16]

        if len(barr) != 16:
            padingbyte = ord(chr(16 - len(barr) % 16))
            numbertoadd = 16 - len(barr) % 16
            barrpad = bytearray(len(barr) + numbertoadd)

            for i in range(len(barr)):
                barrpad[i] = barr[i]

            for i2 in range(len(barrpad) - len(barr)):
                barrpad[i2 + len(barr)] = padingbyte

        cryptor = AES.new(key.encode("utf8"), AES.MODE_ECB)
        ciphertext = cryptor.encrypt(barrpad)
        return ciphertext

    def PKV3(self, i, i2, i3):

        self.roomEvents = 0
        self.guestEvents = 0
        bytes1 = bytes(self.roomMainKey, "utf-8")

        # serialNumber = sendinf.serialNumber
        bArr6 = bytearray(256)
        bArr6[0] = 170
        bArr6[3] = i.to_bytes(1, "little")[0]
        bArr6[4] = i2.to_bytes(1, "little")[0]
        bArr6[5] = i3.to_bytes(1, "little")[0]
        bArr6[6] = 0
        bArr6[7] = 0
        i9 = 8
        if i2 == 3:

            if i3 == 17 or i3 == 18:
                bArr6[8] = 1
                systemTime3 = self.systemTime
                o = systemTime3 >> 24
                p = systemTime3 >> 16
                l = systemTime3 >> 8
                bArr6[9] = o.to_bytes(4, "little")[0]
                bArr6[10] = p.to_bytes(4, "little")[0]
                bArr6[11] = l.to_bytes(4, "little")[0]
                print(p.to_bytes(4, "little")[0])
                bArr6[12] = systemTime3.to_bytes(4, "little")[0]
                bArr6[13] = 0
                bArr6[14] = 0
                bArr6[15] = 0
                bArr6[16] = 0
                bArr6[17] = 0

                bArr26 = bytearray(14)
                for i in range(len(bArr26)):
                    bArr26[i] = bArr6[i + 4]
                try:
                    Encrypt6 = self.AESEncrypt(bArr26, self.manufactureKey)

                    for i57 in range(len(Encrypt6)):
                        bArr6[i57 + 4] = Encrypt6[i57]
                    length14 = len(Encrypt6) + 4
                    for i58 in range(len(bArr6) - length14):
                        bArr6[i58 + length14] = 0

                    gensig27 = self.sig2(
                        self.WK(bytes1, self.roomEvents),
                        self.lockEvents,
                        self.Bytes2AsciiString(bArr6, 3, length14),
                    )
                    for i59 in range(len(gensig27)):
                        bArr6[length14 + i59] = gensig27[i59]
                    i9 = 8 + length14
                    i4 = 0
                except Exception as e:
                    print(e)
                    print("AN exception occured")
        i4 = 0
        bArr6[i9] = self.getCheckSum(bArr6, i9 - 3, 3)
        i85 = i9 + 1
        bArr6[1] = 16
        bArr6[2] = i85 - 3
        bArr45 = bytearray(i85)
        while i4 < i85:
            bArr45[i4] = bArr6[i4]
            i4 += 1

        return bArr45


class lockprot:

    offSet = 0

    def beginDirective(self, barr):
        self.otaSend(barr)

    def otaSend(self, bArr):
        self.lastValue = None
        self.otaRecvBuf = None
        if not ((bArr == None) or (len(bArr) == 0)):
            if self.offSet != 0:
                self.offSet = 0

            self.sendInfoByte = bytearray(len(bArr))
            for i in range(len(bArr)):
                self.sendInfoByte[i] = bArr[i]

            self.sendNextFrame()

    def sendNextFrame(self):
        subPackageOTAData = self.subPackageOTAData()
        if subPackageOTAData != None and len(subPackageOTAData) != 0:

            self.finalhex = subPackageOTAData
            return self.finalhex

        else:
            return None

    def subPackageOTAData(self):
        length = len(self.sendInfoByte)
        i = length - self.offSet

        if i <= 0:
            return None

        if length <= 20:
            copyofrange = bytearray(i + 1)

            for j in range(i):
                copyofrange[j] = self.sendInfoByte[self.offSet + j]

            self.offSet = length
            return bytearray.hex(copyofrange)

        if i > 18:
            i = 18
        e = int(self.offSet / 18)
        bArr = bytearray(20)
        bArr[0] = 255
        bArr[1] = (e).to_bytes(1, "little")[0]
        for i2 in range(i):
            bArr[i2 + 2] = self.sendInfoByte[self.offSet + i2]

        self.offSet += i
        return bytearray.hex(bArr)
