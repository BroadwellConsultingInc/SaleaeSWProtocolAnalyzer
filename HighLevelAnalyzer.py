# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
#    my_string_setting = StringSetting()
#    my_number_setting = NumberSetting(min_value=0, max_value=100)
    serialWombatInterface = ChoicesSetting(label='serialWombatInterface',choices=('I2C', 'UART COMMAND', 'UART RESPONSE'))

    
    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'SW I2C Packet': {
            'format': '[{{data.address}}]  {{data.data}}'
        },
        'SW UART Packet': {
            'format': '{{data.data}}'
        }
    }
    wombat_frame = None
    dataList = [0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55]
    dataCount = 0
    address_byte = 0
    isResponse = True;


    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''

        print("Settings:", #self.my_string_setting,
             # self.my_number_setting, 
              self.serialWombatInterface)

    def uint8(self,index):
          return f'{self.dataList[index]}'
    def uint16(self,index):
          return f'{self.dataList[index] + self.dataList[index + 1] * 256}'
    def hex2(self,index):
          return f'0x{"{:02X} ".format(self.dataList[index])}'

    def hex4(self,index):
          return f'0x{"{:04X} ".format(self.dataList[index] + self.dataList[index + 1] * 256)}'

    def hex8(self,index):
          return f'0x{"{:08X} ".format(self.dataList[index] + self.dataList[index + 1] * 256 + self.dataList[index + 2] * 65536 + self.dataList[index + 3] * 65536 * 256 )}'

    def dec2(self,index):
          return f'{self.dataList[index] }'

    def dec4(self,index):
          return f'{self.dataList[index] + self.dataList[index + 1] * 256}'

    def dec8(self,index):
          return f'{self.dataList[index] + self.dataList[index + 1] * 256 + self.dataList[index + 2] * 65536 + self.dataList[index + 3] * 65536 * 256 }'

    def hex(self,index):
          return self.hex2(index)

    def pinModeName(self, mode):
        pinModeNames = {
            0: 'Digital I/O',
            1: 'Controlled',
            2: 'Analog Input',
            3: 'Servo',
            4: 'Throughput Consumer',
            5: 'Quadrature Encoder',
            6: 'H Bridge',
            7: 'Watchdog',
            8: 'Protected Output',
            10: 'Debounce',
            11: 'TM1637',
            12: 'WS2812',
            13: 'Software UART',
            14: 'Input Processor',
            15: 'Matrix Keypad',
            16: 'PWM',
            17: 'UART RX/TX',
            18: 'Pulse Timer',
            21: 'Frame Timer',
            22: 'Cap Touch 18AB',
            23: 'UART1 RX/TX',
            24: 'Resistance Input',
            25: 'Pulse On Change',
            26: 'High Frequency Servo',
            27: 'Ultrasonic Distance Sensor',
            28: 'Liquid Crystal',
            29: 'High Speed Clock',
            30: 'High Speed Counter',
            31: 'VGA',
            32: 'PS/2 Keyboard',
            33: 'I2C Controller',
            34: 'Queued Pulse Output',
            36: 'Frequency Output',
            37: 'IR Rx',
            38: 'IR Tx',
            40: 'Blink',
            41: 'SPI',
            42: 'Random Blink',
            43: 'Charlieplex',
            255: 'Unknown'
        }
        return pinModeNames.get(mode, f'Mode {mode}')

    def bytesToHex(self, start, end):
          return "".join('{:02X} '.format(x) for x in self.dataList[start:end])

    def unknown(self): # comment me out to cause errors when unknown frames are received.  Good for checking protocol coverage completeness during unit/system testing.
        return

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''

        # Return the data frame itself

        if self.wombat_frame is None:
            self.wombat_frame = AnalyzerFrame("error", frame.start_time, frame.end_time, {
                    "address": "error",
                    "count": 0,
                    "read": False ,
                    "data":''
                    }
            )
            self.dataList = [0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55]
            self.dataCount = 0

        if frame.type == "start" or (frame.type == "address" and self.wombat_frame.type == "error"):
            self.wombat_frame = AnalyzerFrame("SW I2C Packet", frame.start_time, frame.end_time, {
                    "address": "error",
                    "count": 0,
                    "read": False,
                    "data":'Unknown Packet'
                    }
            )
            self.dataList = [0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55]
            self.dataCount = 0

        elif frame.type == "address":
            self.address_byte = frame.data["address"][0]
            self.wombat_frame.data["address"] ='{:02X} '.format(frame.data["address"][0])
            self.isResponse = frame.data["read"];

        elif frame.type == "data":
            if (self.dataCount < 8):
                data_byte = frame.data["data"][0]
                self.dataList[self.dataCount] = data_byte
                self.dataCount += 1
                if (self.serialWombatInterface == "UART COMMAND" or self.serialWombatInterface == "UART RESPONSE"):
                    self.isResponse = self.serialWombatInterface == "UART RESPONSE";
                    if (self.dataCount == 1 and self.dataList[0] == 0x55):
                        self.dataCount = 0
                        return 

                    if (self.dataCount == 1):
                        self.wombat_frame = AnalyzerFrame("SW UART Packet",frame.start_time, frame.end_time,{"count":0, "data":"Unknown Packet"})
                        self.wombat_frame.start_time = frame.start_time

                    if (self.dataCount >= 8):
                        self.wombat_frame.end_time = frame.end_time
                        self.generateString()
                        new_frame = self.wombat_frame
                        self.dataCount = 0
                        self.wombat_frame = None
                        return new_frame

                    

        elif frame.type == "stop":
            self.wombat_frame.end_time = frame.end_time
            self.generateString();
            new_frame = self.wombat_frame
            self.wombat_frame = None
            if (self.address_byte >= 0x60 and self.address_byte <= 0x6F):
                self.address_byte = 0
                return new_frame
            else:
                self.address_byte = 0


    def generateString(self):
        outstr = ""

        if self.isResponse:
            outstr = "RESP: "
        else:
            outstr = "CMD: "

        if self.dataCount < 8:
            outstr += "ERROR:  Short Frame"
        elif self.dataList[0] == 0x21:
            outstr = outstr + self.echo()
        elif self.dataList[0] == 0x40:  # @ symbol
            outstr = outstr + self.testResult()
        elif self.dataList[0] == 0x42:
            outstr = outstr + self.bootload()
        elif self.dataList[0] == 0x45:
            outstr = outstr + self.error()
        elif self.dataList[0] == 0x52:
            outstr = outstr + self.reset()
        elif self.dataList[0] == 0x53:
            outstr = outstr + self.sleep()
        elif self.dataList[0] == 0x55:
            outstr = outstr + self.resync()
        elif self.dataList[0] == 0x56:
            outstr = outstr + self.version()
        elif self.dataList[0] == 0x5E:
            outstr = outstr + self.lineBreak()
        elif self.dataList[0] == 0x76:
            outstr = outstr + self.supplyVoltage()
        elif self.dataList[0] == 0x64:
            outstr = outstr + self.asciiSetData()
        elif self.dataList[0] == 0x47:
            outstr = outstr + self.asciiGetData()
        elif self.dataList[0] == 0x67:
            outstr = outstr + self.asciiGetData()
        elif self.dataList[0] == 0x50:
            outstr = outstr + self.asciiSetPin()
        elif self.dataList[0] == 0x70:
            outstr = outstr + self.asciiSetPin()
        elif self.dataList[0] == 0x81:
            outstr = outstr + self.readPin()
        elif self.dataList[0] == 0x82:
            outstr = outstr + self.writePin()
        elif self.dataList[0] == 0x83:
            outstr = outstr + self.readUserBuffer()
        elif self.dataList[0] == 0x84:
            outstr = outstr + self.writeUserBuffer()
        elif self.dataList[0] == 0x85:
            outstr = outstr + self.writeUserBufferContinue()
        elif self.dataList[0] == 0x8F:
            outstr = outstr + self.pinPollThreshold()
        elif self.dataList[0] == 0x90:
            outstr = outstr + self.queueInit()
        elif self.dataList[0] == 0x91:
            outstr = outstr + self.queueAdd()
        elif self.dataList[0] == 0x92:
            outstr = outstr + self.queueAdd7()
        elif self.dataList[0] == 0x93:
            outstr = outstr + self.queueRead()
        elif self.dataList[0] == 0x94:
            outstr = outstr + self.queueInfo()
        elif self.dataList[0] == 0x95:
            outstr = outstr + self.queueClone()        
        elif self.dataList[0] == 0x96:
            outstr = outstr + self.dataLogger()
        elif self.dataList[0] == 0x9F:
            outstr = outstr + self.configureGeneric()
        elif  self.dataList[0] == 0xA0:
            outstr = outstr + self.readRam() 
        elif  self.dataList[0] == 0xA1:
            outstr = outstr + self.readFlash() 
        elif  self.dataList[0] == 0xA2:
            outstr = outstr + self.readEeprom() 
        elif  self.dataList[0] == 0xA3:
            outstr = outstr + self.writeRam() 
        elif  self.dataList[0] == 0xA4:
            outstr = outstr + self.writeFlash() 
        elif  self.dataList[0] == 0xA5:
            outstr = outstr + self.calibrateAnalog() 
        elif  self.dataList[0] == 0xA6:
            outstr = outstr + self.enable2ndUART() 
        elif  self.dataList[0] == 0xA7:
            outstr = outstr + self.readLastErrorPacket() 
        elif  self.dataList[0] == 0xB0:
            outstr = outstr + self.UART1TX7() 
        elif  self.dataList[0] == 0xB1:
            outstr = outstr + self.UART1RX7() 
        elif  self.dataList[0] == 0xB2:
            outstr = outstr + self.UART2TX7() 
        elif  self.dataList[0] == 0xB3:
            outstr = outstr + self.UART2RX7() 
        elif  self.dataList[0] == 0xB4:
            outstr = outstr + self.testSequence() 
        elif  self.dataList[0] == 0xB5:
            outstr = outstr + self.rwPinMemory() 
        elif  self.dataList[0] == 0xB6:
            outstr = outstr + self.captureStartupSequence() 
        elif  self.dataList[0] == 0xB7:
            outstr = outstr + self.adjustFrequency() 
        elif self.dataList[0] == 0xB8:
            outstr = outstr + self.setPinHardware() 
        elif self.dataList[0] == 0xB9:
            outstr = outstr + self.setAddress() 
        elif self.dataList[0] == 0xD2: #Output Scaling generic
            outstr = outstr + self.configureOutputScaling() 
        elif self.dataList[0] == 0xD3: #input processor generic
            outstr = outstr + self.configureInputProcessor() 
        elif self.dataList[0] == 0xD4: #SWI2C generic
            outstr = outstr + self.configureSWI2C() 
        elif self.dataList[0] == 0xDA:
            outstr = outstr + self.checkPinModeSupported()
        elif self.dataList[0] == 0xDB:
            outstr = outstr + self.disablePin() 
        elif (self.dataList[0] >= 0xC8 and self.dataList[0] <= 0xD1) or (self.dataList[0] >= 0xDC and self.dataList[0] <= 0xDF):
            outstr = outstr + self.configurePin() 

        else:
            outstr += 'Unknown command ' + self.hex2(0) + ' Data: ' + self.bytesToHex(1,8)
            self.unknown()

        self.wombat_frame.data["data"] = outstr

    def echo(self):
        outstr = "Echo: "
        outstr =  outstr +  "".join('{:02X} '.format(x) for x in self.dataList[-7:])
        return outstr

    def testResult(self):
        outstr = "Test result: "
        if (self.dataList[1] == 1):
            #pass
            outstr = outstr + "Pass "
        else:
            outstr = outstr + "Fail "
        outstr = outstr + f'X: {self.hex4(2)} {self.dataList[2] + self.dataList[3] * 256} V: {self.hex4(4)} {self.dataList[4] + self.dataList[5] * 256}'
        return outstr

    def bootload(self):
        outstr = "Bootload "
        bootStr =  "".join(chr(x) for x in self.dataList)
        if ( bootStr != "BoOtLoAd"):
            outstr += " ERROR! Wrong String " + bootStr;
        return outstr

    errorStrings = [
        'SW_ERROR_UNNUMBERED_ERROR', # = 0
        'SW_ERROR_PINS_MUST_BE_ON_SAME_PORT', # = 1
        'SW_ERROR_ASCII_NUMBER_TOO_BIG_16', # = 2
        'SW_ERROR_UNKNOWN_PIN_MODE', # = 3
        'SW_ERROR_RESET_STRING_INCORRECT', # = 4
        'SW_ERROR_INVALID_COMMAND', # = 5
        'SW_ERROR_INSUFFICIENT_SPACE', # = 6
        'SW_ERROR_WUB_COUNT_GT_4', # = 7
        'SW_ERROR_WUB_INVALID_ADDRESS', # = 8
        'SW_ERROR_WUB_CONTINUE_OUTOFBOUNDS', # = 9
        'SW_ERROR_RF_ODD_ADDRESS', # = 10
        'SW_ERROR_FLASH_WRITE_INVALID_ADDRESS', # = 11
        'SW_ERROR_INVALID_PIN_COMMAND', # = 12
        'SW_ERROR_PIN_CONFIG_WRONG_ORDER', # = 13
        'SW_ERROR_WS2812_INDEX_GT_LEDS', # = 14
        'SW_ERROR_PIN_NOT_CAPABLE', # = 15
        'SW_ERROR_HW_RESOURCE_IN_USE', # = 16
        'SW_ERROR_INVALID_PARAMETER_3', # = 17
        'SW_ERROR_INVALID_PARAMETER_4', # = 18
        'SW_ERROR_INVALID_PARAMETER_5', # = 19
        'SW_ERROR_INVALID_PARAMETER_6', # = 20
        'SW_ERROR_INVALID_PARAMETER_7', # = 21
        'SW_ERROR_PIN_NUMBER_TOO_HIGH', # = 22
        'SW_ERROR_PIN_IS_COMM_INTERFACE', # = 23
        'SW_ERROR_ANALOG_CAL_WRONG_UNLOCK', # = 24
        'SW_ERROR_2ND_INF_WRONG_UNLOCK', # = 25
        'SW_ERROR_2ND_INF_UNAVAILABLE', # = 26
        'SW_ERROR_UART_NOT_INITIALIZED', # = 27
        'SW_ERROR_CMD_BYTE_1', # = 28
        'SW_ERROR_CMD_BYTE_2', # = 29
        'SW_ERROR_CMD_BYTE_3', # = 30
        'SW_ERROR_CMD_BYTE_4', # = 31
        'SW_ERROR_CMD_BYTE_5', # = 32
        'SW_ERROR_CMD_BYTE_6', # = 33
        'SW_ERROR_CMD_BYTE_7', # = 34
        'SW_ERROR_CMD_UNSUPPORTED_BAUD_RATE', # = 35
        'SW_ERROR_QUEUE_RESULT_INSUFFICIENT_USER_SPACE', # = 36
        'SW_ERROR_QUEUE_RESULT_UNALIGNED_ADDRESS', # = 37
        'SW_ERROR_QUEUE_RESULT_INVALID_QUEUE', # = 38
        'SW_ERROR_QUEUE_RESULT_FULL', # = 39
        'SW_ERROR_QUEUE_RESULT_EMPTY', # = 40
        'SW_ERROR_DATA_NOT_AVAILABLE', # = 41
        'SW_ERROR_TM1637_WRONG_MODE', # = 42
        'SW_ERROR_RUB_INVALID_ADDRESS', # = 43
        'SW_ERROR_UNKNOWN_OUTPUTSCALE_COMMAND', # = 44
        'SW_ERROR_UNKNOWN_INPUT_PROCESS_COMMAND', # = 45
        'SW_ERROR_PULSE_ON_CHANGE_ENTRY_OUT_OF_RANGE', # = 46
        'SW_ERROR_PULSE_ON_CHANGE_UNKNOWN_MODE', # = 47
        'SW_ERROR_LESS_THAN_8_BYTES_RETURNED', # = 48
        'SW_ERROR_REENTRANCY_NOT_SUPPORTED', # = 49
        'SW_ERROR_CLASS_INIITALIZATION_ERROR', # = 50
        'SW_ERROR_WRONG_CHIP_TYPE', # = 51
        'SW_ERROR_WRONG_CHIP_FIRMWARE_VERSION', # = 52
    ]


    def error(self):
        outstr = "ERROR: "
        errornum = ((self.dataList[1] - 0x30) * 10000 +
                   (self.dataList[2] - 0x30) * 1000 +
                   (self.dataList[3] - 0x30) * 100 +
                   (self.dataList[4] - 0x30) * 10 +
                   (self.dataList[5] - 0x30)) 
        if (errornum < len(self.errorStrings) and errornum >= 0 ):
            outstr += self.errorStrings[errornum];
        else:
            outstr += f' Unknown error {errornum}'
            self.unknown()
        return outstr

    def reset(self):
#        if ("".join(self.dataList[0:8]) == "ReSeT!#*"):
#            outstr = "Reset Command"
#        else:
#            outstr = "Reset Wrong Command"
        return "Reset Command"

    def sleep(self):
        if self.dataList[1] == ord('l') and self.dataList[2] == ord('E') and self.dataList[3] == ord('e') and self.dataList[4] == ord('P'):
            if self.dataList[6] == ord('#') and self.dataList[7] == ord('*'):
                return 'Sleep Command'
            else:
                return f'Sleep Command delay {self.uint16(6)} mS'
        return self.asciiSetData()

    def resync(self):
        return 'Resync / sync byte packet'

    def supplyVoltage(self):
        if self.isResponse:
            return f'Supply Voltage response: {self.uint16(1)} mV Raw: {self.bytesToHex(1,8)}'
        else:
            return 'Supply Voltage Request'

    def readUserBuffer(self):
        address = self.dataList[1] + 256 * self.dataList[2] 
        if self.isResponse:
            value =self.dataList[3]
            return f'Read Result: {self.hex2(1)} {self.hex2(2)} {self.hex2(3)} {self.hex2(4)} {self.hex2(5)} {self.hex2(6)} {self.hex2(7)}'
        else:
            return f'Read User Buffer Index: 0x{"{:04X} ".format(address)}'


    def writeUserBuffer(self):
        address = self.dataList[1] + 256 * self.dataList[2] 
        count =self.dataList[3]
        return f'Write User buffer: Addr: 0x{"{:04X} ".format(address)} count: {count} {"".join("{:02x} ".format(x) for x in self.dataList[4:4 + count])} '

    def writeUserBufferContinue(self):
        return f'Write User buffer Continue:  {"".join("{:02x} ".format(x) for x in self.dataList[1:8])} '

    def pinPollThreshold(self):
        if self.isResponse:
            return f'Pin Poll Threshold Response: {self.bytesToHex(1,8)}'
        else:
            return f'Pin Poll Threshold: {self.uint16(1)}'

    def dataLogger(self):
        cmd = self.dataList[1]
        if cmd == 0:
            return f'Data Logger Init: Queue Address {self.hex4(2)} Period enum {self.dataList[4]} Queue frame index {self.dataList[5]} Queue on change {self.dataList[6]}'
        elif cmd == 1:
            return f'Data Logger Enable: {self.dataList[2]}'
        elif cmd == 2:
            return f'Data Logger Configure Pin: Pin {self.dataList[2]} Queue low byte {self.dataList[3]} Queue high byte {self.dataList[4]}'
        else:
            self.unknown()
            return f'Data Logger Unknown command {cmd}: {self.bytesToHex(2,8)}'

    def configureGeneric(self):
        return f'Generic Configure command: {self.bytesToHex(1,8)}'

    def readEeprom(self):
        address = self.dataList[1] + 256 * self.dataList[2] + self.dataList[3] * 65536
        if self.isResponse:
            return f'Read EEPROM Address: 0x{address:06X} Data: {self.bytesToHex(4,8)}'
        else:
            return f'Read EEPROM Address: 0x{address:06X}'

    def setPinHardware(self):
        outstr = f'Set Pin Hardware pin {self.dataList[1]}:'
        if self.dataList[2] != 0x55:
            outstr += f' Pullup {self.dataList[2]}'
        if self.dataList[3] != 0x55:
            outstr += f' Pulldown {self.dataList[3]}'
        if self.dataList[4] != 0x55:
            outstr += f' OpenDrain/ForceDMA {self.dataList[4]}'
        if outstr.endswith(':'):
            outstr += ' no fields changed'
        return outstr

    def setAddress(self):
        address = self.dataList[1] + self.dataList[2] * 256 + self.dataList[3] * 65536 + self.dataList[4] * 16777216
        return f'Set Address: 0x{address:08X}'


    def readRam(self):
        address = self.dataList[1] + 256 * self.dataList[2] 
        if self.isResponse:
            value =self.dataList[3]
            return f'Read RAM Address: 0x{"{:04X} ".format(address)} Value: {value}/0x{"{:02X} ".format(value)} '
        else:
            return f'Read RAM Address: 0x{"{:04X} ".format(address)}'

    def readFlash(self):
        address = self.dataList[1] + 256 * self.dataList[2] + self.dataList[3] * 65536
        if self.isResponse:
            value =self.dataList[4] + self.dataList[5] * 256 + self.dataList[6] * 65536 + self.dataList[7] * 65536 * 256
            return f'Read Flash Address: 0x{"{:04X} ".format(address)} Value: {value}/0x{"{:04X} ".format(value)} '
        else:
            return f'Read Flash Address: 0x{"{:04X} ".format(address)}'

    def writeRam(self):
        address = self.dataList[1] + 256 * self.dataList[2]  + self.dataList[3] * 65536 + self.dataList[4] * 256 * 65536
        value =self.dataList[5]
        return f'Write RAM Address: 0x{"{:04X} ".format(address)} Value: {value}/0x{"{:02X} ".format(value)} '

    def writeFlash(self):
        if (self.dataList[1] == 0):
            address = self.dataList[2] + 256 * self.dataList[3]  + self.dataList[4] * 65536 + self.dataList[5] * 256 * 65536
            return f'Erase block at : 0x{"{:08X} ".format(address)} '
        elif (self.dataList[1] == 1):
            address = self.dataList[2] + 256 * self.dataList[3]  + self.dataList[4] * 65536 + self.dataList[5] * 256 * 65536
            return f'Write block at : 0x{"{:08X} ".format(address)} '
        elif (self.dataList[1] == 2):
            if self.isResponse:
                crc = self.dataList[2] + 256 * self.dataList[3]
                return f'CRC Result : 0x{"{:04X} ".format(crc)} '
            else:
                return 'CRC App space '


        else:
            self.unknown();
            return 'Unknown flash write command'

    def calibrateAnalog(self):
        return 'Calibrate Analog'

    def enable2ndUART(self):
        return f'Enable 2nd Interface: {self.dataList[1]} Unlock req: B2 A5 61 73 F8 A2 '

    def readLastErrorPacket(self):
        address = self.dataList[1] + 256 * self.dataList[2] + self.dataList[3] * 65536
        if self.isResponse:
            value =self.dataList[4] + self.dataList[5] * 256 + self.dataList[6] * 65536 + self.dataList[7] * 65536 * 256
            return f'Read Last Error Packet: {self.hex2(1)} {self.hex2(2)} {self.hex2(3)} {self.hex2(4)} {self.hex2(5)} {self.hex2(6)} {self.hex2(7)}'
        else:
            return f'Read Last Error Packet starting byte {self.dataList[1]}'

    def UART1TX7(self):
        if self.isResponse:
            return f'UART TX1 7 BYTES echo'
        else:
            return f'UART TX1 7 BYTES: {self.hex2(1)} {self.hex2(2)} {self.hex2(3)} {self.hex2(4)} {self.hex2(5)} {self.hex2(6)} {self.hex2(7)} '

    def disablePin(self):
            return f'Disable pin {self.dataList[1]}, mode {self.dataList[2]}'
            
    def UART1RX7(self):
        if self.isResponse:
            return f'UART RX1 7 BYTES: {self.hex2(1)} {self.hex2(2)} {self.hex2(3)} {self.hex2(4)} {self.hex2(5)} {self.hex2(6)} {self.hex2(7)} '
        else:
            return f'UART RX1 7 BYTES echo'

    def UART2TX7(self):
        if self.isResponse:
            return f'UART TX2 7 BYTES echo'
        else:
            return f'UART TX2 7 BYTES: {self.hex2(1)} {self.hex2(2)} {self.hex2(3)} {self.hex2(4)} {self.hex2(5)} {self.hex2(6)} {self.hex2(7)} '
            
    def UART2RX7(self):
        if self.isResponse:
            return f'UART RX2 7 BYTES: {self.hex2(1)} {self.hex2(2)} {self.hex2(3)} {self.hex2(4)} {self.hex2(5)} {self.hex2(6)} {self.hex2(7)} '
        else:
            return f'UART RX2 7 BYTES echo'
    
    def testSequence(self):
        return f'Test Sequence'

    def rwPinMemory(self):
        if (self.dataList[1] == 0):
            if self.isResponse:
                return f'Pin Byte BYTES: {self.hex2(1)} {self.hex2(2)} {self.hex2(3)} {self.hex2(4)} {self.hex2(5)} {self.hex2(6)} {self.hex2(7)} '
            else:
                return f'Read 7 bytes from pin {self.dataList[2]} offset {self.dataList[3]}' 
        else:
            self.unknown();
            return f'Unknown pin memory RW command'

    def captureStartupSequence(self):
        if (self.dataList[1] == 0):
            return f'Start Startup Sequence Capture' 
        elif (self.dataList[1] == 1):
            return f'Stop Startup Sequence Capture' 
        elif (self.dataList[1] == 2):
            return f'Store Startup Sequence Capture' 
        else:
            self.unknown();
            return f'Unknown Startup Sequence Capture command'

    def adjustFrequency(self):
        if self.isResponse:
            return f'Adjust frequency: New register setting: {self.hex4(5)}' 
        else:
            return f'Adjust frequency:  Increment {self.dec2(1)} steps, decrement {self.dec2(3)} steps' 



    def version(self):
        if self.isResponse:
            category = chr(self.dataList[1])
            model = ''.join(chr(x) for x in self.dataList[2:5])
            ver =''.join(chr(x) for x in self.dataList[5:8])
            return f'Version-- Category: {category} Model: {model} FW Ver: {ver} '
        else:
            return "Version "

    def lineBreak(self):
        return f'LineBreak Enable/Disable'

    def asciiSetData(self):
        pin =  (self.dataList[1] - 0x30) * 10 + (self.dataList[2] - 0x30) 
        return f'Ascii Set public data pin: {pin}: {chr(self.dataList[3])}{chr(self.dataList[4])}{chr(self.dataList[5])}{chr(self.dataList[6])}{chr(self.dataList[7])}'

    def asciiGetData(self):
        if self.isResponse:
            return f'Get data Result: {chr(self.dataList[3])}{chr(self.dataList[4])}{chr(self.dataList[5])}{chr(self.dataList[6])}{chr(self.dataList[7])}'
        else:
            pin = (self.dataList[1] - 0x30) * 100 + (self.dataList[2] - 0x30) * 10 + (self.dataList[3] - 0x30) 
            return f'Ascii get public data pin:  {pin} '

    def asciiSetPin(self):
        pin = (self.dataList[1] - 0x30) * 10 + self.dataList[2] - 0x30;
        return f'Ascii Set pin:  P{pin} {chr(self.dataList[3])} P{pin + 1} {chr(self.dataList[4])} P{pin + 2} {chr(self.dataList[5])} P{pin + 3} {chr(self.dataList[6])} P{pin + 4}{chr(self.dataList[7])}'

    def readPin(self):
        if self.isResponse:
            if (self.dataList[1] == 0x41):
                return f'Read incrementingCounter: {self.dataList[2] + self.dataList[3] * 256 + self.dataList[4] * 65536 + self.dataList[5] * 256 * 65536}'
            elif (self.dataList[1] == 0x42):
                return f'Read 1.024 V reference:({hex( (self.dataList[2] + self.dataList[3] * 256)) }).  Inferred Vcc: {int( 1024.0 * 65536 /(self.dataList[2] + self.dataList[3] * 256))} mv '
            elif (self.dataList[1] == 0x43):
                return f'Read Frames Run LSW: {self.dataList[2] + self.dataList[3] * 256 + self.dataList[4] * 65536 + self.dataList[5] * 256 * 65536}'
            elif (self.dataList[1] == 0x44):
                return f'Read Frames Run MSW: {self.dataList[2] + self.dataList[3] * 256 + self.dataList[4] * 65536 + self.dataList[5] * 256 * 65536}'
            elif (self.dataList[1] == 0x45):
                return f'Read Overflow Frames: {self.dataList[2] + self.dataList[3] * 256}'
            elif (self.dataList[1] == 0x46):
                return f'Read Temperature: {self.dataList[2] + self.dataList[3] * 256} 100ths deg C'
            elif (self.dataList[1] == 0x47):
                return f'Read Packets Processed: {self.dataList[2] + self.dataList[3] * 256}'
            elif (self.dataList[1] == 0x48):
                return f'Read Errors: {self.dataList[2] + self.dataList[3] * 256}'
            elif (self.dataList[1] == 0x49):
                return f'Read Frames Dropped: {self.dataList[2] + self.dataList[3] * 256}'
            elif (self.dataList[1] == 0x4A):
                return f'Read System Utilization average: {self.dataList[2] + self.dataList[3] * 256}'
            else:
                return f'Read Pin {self.dataList[1]}: {self.dataList[2] + self.dataList[3] * 256} / {hex(self.dataList[2] + self.dataList[3] * 256)}, {self.dataList[1] + 1}: {self.dataList[4] + self.dataList[5] * 256} / {hex(self.dataList[4] + self.dataList[5] * 256)}, {self.dataList[1] + 2}: {self.dataList[6] + self.dataList[7] * 256} / {hex(self.dataList[6] + self.dataList[7] * 256)}'
        else:
            if (self.dataList[1] == 0x40):
                return 'Read incrementingCounter'
            elif (self.dataList[1] == 0x42):
                return 'Read 1.024 V reference'
            elif (self.dataList[1] == 0x43):
                return 'Read Frames Run'
            elif (self.dataList[1] == 0x45):
                return 'Read OverFlow Frames'
            else:
                return f'Read Pin {self.dataList[1]}'
            

    def writePin(self):
        outstr = f'Write Pin {self.dataList[1]}: {self.dataList[2] + self.dataList[3] * 256} / {hex(self.dataList[2] + self.dataList[3] * 256)}'
        if (self.dataList[4] != 0xFF):
            outstr = outstr + f',  {self.dataList[4]}: {self.dataList[5] + self.dataList[6] * 256} / {hex(self.dataList[5] + self.dataList[6] * 256)}'
        return outstr


    def configurePin(self):
        if self.dataList[0] == 0xDA:
            return self.checkPinModeSupported()
        if self.dataList[2] == 0:
            return self.setDigitalIO();
        elif self.dataList[2] == 1:
            return self.setControlled();
        elif self.dataList[2] == 2:
            return self.setAnalogInput();
        elif self.dataList[2] == 3:
            return self.setServo();
        elif self.dataList[2] == 4:
            return self.setThroughputConsumer();
        elif self.dataList[2] == 5:
            return self.setQuadEnc();
        elif self.dataList[2] == 6:
            return self.setHBridge();
        elif self.dataList[2] == 7:
            return self.setWatchdog();
        elif self.dataList[2] == 8:
            return self.setProtectedOutput();
        elif self.dataList[2] == 10:
            return self.setDebounce();
        elif self.dataList[2] == 11:
            return self.setTM1637();
        elif self.dataList[2] == 12:
            return self.setWS2812();
        elif self.dataList[2] == 14:  #13 covered below
            return self.setInputProcessor(); 
        elif self.dataList[2] == 15: 
            return self.setMatrixKeypad(); 
        elif self.dataList[2] == 16:
            return self.setPWM();
        elif self.dataList[2] == 17  or self.dataList[2] == 13  or self.dataList[2] == 23:
            return self.setUARTTXRX();
        elif self.dataList[2] == 18:
            return self.setPulseTimer();
        elif self.dataList[2] == 21:
            return self.setFrameTimer();
        elif self.dataList[2] == 22:
            return self.setCapTouch18();
        elif self.dataList[2] == 24:
            return self.setResistanceInput();
        elif self.dataList[2] == 25:
            return self.setPulseOnChange();
        elif self.dataList[2] == 26:
            return self.setHFServo();
        elif self.dataList[2] == 27:
            return self.setUltrasonicDistanceSensor();
        elif self.dataList[2] == 28:
            return self.setLiquidCrystal();
        elif self.dataList[2] == 29:
            return self.setHSClock();
        elif self.dataList[2] == 30:
            return self.setHSCounter();
        elif self.dataList[2] == 31:
            return self.setVGA();
        elif self.dataList[2] == 32:
            return self.setPS2Keyboard();
        elif self.dataList[2] == 33:
            return self.setI2CController();
        elif self.dataList[2] == 34:
            return self.setQueuedPulseOutput();
        elif self.dataList[2] == 36:
            return self.setFrequencyOutput();
        elif self.dataList[2] == 37:
            return self.setIRRx();
        elif self.dataList[2] == 38:
            return self.setIRTx();
        elif self.dataList[2] == 40:
            return self.setBlink();
        elif self.dataList[2] == 41:
            return self.setSPI();
        elif self.dataList[2] == 42:
            return self.setRandomBlink();
        elif self.dataList[2] == 43:
            return self.setCharlieplex();
        else:
            return f'Configure Pin {self.dataList[1]} {self.pinModeName(self.dataList[2])} raw packet {self.hex2(0)} {self.bytesToHex(3,8)}'

    def checkPinModeSupported(self):
        if self.isResponse:
            return f'Check Pin Mode Supported: {self.pinModeName(self.dataList[2])} Result: {self.dataList[3]} Raw: {self.bytesToHex(1,8)}'
        else:
            return f'Check Pin Mode Supported: {self.pinModeName(self.dataList[2])}'

    def configureInputProcessor(self):
        if (self.dataList[3] == 0):
            return f'Configure Pin {self.dataList[1]} Input Processing enabled {self.dataList[4]}'
        elif (self.dataList[3] == 1):
            return f'Configure Pin {self.dataList[1]} IP SamplesToAverage: {self.dataList[4] + 256 * self.dataList[5]} FilterConstant: {self.dataList[6] + 256 * self.dataList[7]}'
        elif (self.dataList[3] == 2):
            return f'Configure Pin {self.dataList[1]} IP ExcludeBelow: {self.dataList[4] + 256 * self.dataList[5]} ExcludeAbove: {self.dataList[6] + 256 * self.dataList[7]}'
        elif (self.dataList[3] == 3):
            return f'Configure Pin {self.dataList[1]} IP Invert {self.dataList[4]}'
        elif (self.dataList[3] == 4):
            return f'Configure Pin {self.dataList[1]} IP Public Data Mode: {self.dataList[4]}'
        elif (self.dataList[3] == 5):
            return f'Configure Pin {self.dataList[1]} IP Queue: {self.dataList[4] + 256 * self.dataList[5]} Freq: {self.dataList[6]} HBLB: {self.dataList[7]}'
        elif (self.dataList[3] == 6):
            return f'Configure Pin {self.dataList[1]} IP ScaleRange Mode - Low:{self.dataList[4] + 256 * self.dataList[5]} High:{self.dataList[6] + 256 * self.dataList[7]}'
        elif (self.dataList[3] == 7):
            return f'Configure Pin {self.dataList[1]} IP Slope Int32'
        elif (self.dataList[3] == 8):
            return f'Configure Pin {self.dataList[1]} IP Offset Int32'
        elif (self.dataList[3] == 9):
            if self.isResponse:
                return f'Set pin {self.dataList[1]} IP read Min: {self.dataList[4] + self.dataList[5] * 256}'
            else:
                return f'Set pin {self.dataList[1]} IP read Min. Reset: {self.dataList[4]}' 
        elif (self.dataList[3] == 10):
            if self.isResponse:
                return f'Set pin {self.dataList[1]} IP read Max: {self.dataList[4] + self.dataList[5] * 256}'
            else:
                return f'Set pin {self.dataList[1]} IP read Max. Reset: {self.dataList[4]}' 
        elif (self.dataList[3] == 11):
            if self.isResponse:
                return f'Set pin {self.dataList[1]} IP read avg: {self.dataList[4] + self.dataList[5] * 256} filtered: {self.dataList[6] + self.dataList[7] * 256}'
            elif self.dataList[4] != 0x55 or self.dataList[5] != 0x55:
                return f'Configure Pin {self.dataList[1]} IP First Order Filter Constant: {self.uint16(4)}'
            else:
                return f'Set pin {self.dataList[1]} IP read avg, filtered' 
        elif (self.dataList[3] == 12):
            return f'Configure Pin {self.dataList[1]} IP Integrator negative max index {self.uint16(4)} negative mid index {self.uint16(6)}'
        elif (self.dataList[3] == 13):
            return f'Configure Pin {self.dataList[1]} IP Integrator negative dead zone {self.uint16(4)} positive dead zone {self.uint16(6)}'
        elif (self.dataList[3] == 14):
            return f'Configure Pin {self.dataList[1]} IP Integrator positive mid index {self.uint16(4)} positive max index {self.uint16(6)}'
        elif (self.dataList[3] == 15):
            return f'Configure Pin {self.dataList[1]} IP Integrator initial value {self.uint16(4)}'
        elif (self.dataList[3] == 16):
            return f'Configure Pin {self.dataList[1]} IP Integrator mid increment {self.uint16(4)} max increment {self.uint16(6)}'
        elif (self.dataList[3] == 17):
            return f'Configure Pin {self.dataList[1]} IP Integrator update frequency mask {self.dataList[4]}'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} Input Process unknown command {self.dataList[3]}'


    def configureOutputScaling(self): 
        if (self.dataList[3] == 0):
            return f'Configure Pin {self.dataList[1]} Output Scaling enabled {self.dataList[4]}, Source pin {self.dataList[5]}'
        elif (self.dataList[3] == 1):
            return f'Configure Pin {self.dataList[1]} OS Comm Timeout mS: {self.dataList[4] + 256 * self.dataList[5]} Timeout Value: {self.dataList[6] + 256 * self.dataList[7]}'
        elif (self.dataList[3] == 2):
            return f'Configure Pin {self.dataList[1]} OS Input Min: {self.dataList[4] + 256 * self.dataList[5]} input Max: {self.dataList[6] + 256 * self.dataList[7]}'
        elif (self.dataList[3] == 3):
            return f'Configure Pin {self.dataList[1]} OS Invert {self.dataList[4]}'
        elif (self.dataList[3] == 4):
            return f'Configure Pin {self.dataList[1]} OS Filter Mode: {self.dataList[4]} Filter Constant:{self.dataList[5] + 256 * self.dataList[6]}'
        elif (self.dataList[3] == 5):
            return f'Configure Pin {self.dataList[1]} OS Output Min: {self.dataList[4] + 256 * self.dataList[5]} Output Max: {self.dataList[6] + 256 * self.dataList[7]}'
        elif (self.dataList[3] == 6):
            return f'Configure Pin {self.dataList[1]} OS TargetValue:{self.dataList[4] + 256 * self.dataList[5]}' 
        elif (self.dataList[3] == 7):
            return f'Configure Pin {self.dataList[1]} Sample Rate Enum: {self.dataList[4]}'
        elif (self.dataList[3] == 8):
            return f'Configure Pin {self.dataList[1]} Filter constant : {self.uint16(4)}'
        elif (self.dataList[3] == 9):
            if self.isResponse:
                return f'Set pin {self.dataList[1]} Last Value {self.uint16(4)}'
            else:
                return f'Set pin {self.dataList[1]} Request last value' 
        elif (self.dataList[3] == 10):
            return f'Configure Pin {self.dataList[1]} Linear Interpolation setup address {self.hex4(4)}'  
        elif (self.dataList[3] == 49):
            return f'Configure Pin {self.dataList[1]} Output Transform Mode None'
        elif (self.dataList[3] == 50):
            return f'Configure Pin {self.dataList[1]} OS hysteresis high Limit{self.dataList[4] + 256 * self.dataList[5]} High Output: {self.dataList[6] + 256 * self.dataList[7]}'  
        elif (self.dataList[3] == 51):
            return f'Configure Pin {self.dataList[1]} OS hysteresis Low Limit{self.dataList[4] + 256 * self.dataList[5]} Low Output: {self.dataList[6] + 256 * self.dataList[7]}'  
        elif (self.dataList[3] == 52):
            return f'Configure Pin {self.dataList[1]} OS hysteresis Last value {self.dataList[4] + 256 * self.dataList[5]}'  
        elif (self.dataList[3] == 60):
            return f'Configure Pin {self.dataList[1]} OS Transform Mode Ramp Slow Inc {self.uint16(4)} Increment Diff: {self.uint16(6)}'
        elif (self.dataList[3] == 61):
            return f'Configure Pin {self.dataList[1]} OS Transform Mode Ramp Increment {self.uint16(4)} '
        elif (self.dataList[3] == 100):
            return f'Configure Pin {self.dataList[1]} OS PID  KP: {self.dataList[4] + 256 * self.dataList[5]} KI:{self.dataList[6] + 256 * self.dataList[7]}'  
        elif (self.dataList[3] == 101):
            return f'Configure Pin {self.dataList[1]} OS PID  KD: {self.dataList[4] + 256 * self.dataList[5]} '  
        elif (self.dataList[3] == 102):
            return f'Configure Pin {self.dataList[1]} OS PID  Integrator to zero'
        elif (self.dataList[3] == 103):
            if self.isResponse:
                return f'Set pin {self.dataList[1]} PID Last Error {self.hex8(4)}'
            else:
                return f'Set pin {self.dataList[1]} Request PID last error' 
        elif (self.dataList[3] == 104):
            if self.isResponse:
                return f'Set pin {self.dataList[1]} PID Last Integrator {self.hex8(4)}'
            else:
                return f'Set pin {self.dataList[1]} Request PID last Integrator' 
        elif (self.dataList[3] == 105):
            if self.isResponse:
                return f'Set pin {self.dataList[1]} PID Last Integrator Effort {self.hex8(4)}'
            else:
                return f'Set pin {self.dataList[1]} Request PID last Integrator Effort' 
        elif (self.dataList[3] == 106):
            if self.isResponse:
                return f'Set pin {self.dataList[1]} PID Last Proportional Effort {self.hex8(4)}'
            else:
                return f'Set pin {self.dataList[1]} Request PID last Proportional Effort' 
        elif (self.dataList[3] == 107):
            if self.isResponse:
                return f'Set pin {self.dataList[1]} PID Last Derivative Effort {self.hex8(4)}'
            else:
                return f'Set pin {self.dataList[1]} Request PID last Derivative Effort' 
        elif (self.dataList[3] == 108):
            if self.isResponse:
                return f'Set pin {self.dataList[1]} PID Last Total Effort {self.hex8(4)}'
            else:
                return f'Set pin {self.dataList[1]} Request PID last Total Effort' 
        elif (self.dataList[3] == 109):
            return f'Configure Pin {self.dataList[1]} OS PID  Target pin {self.dataList[4]}  Add 0x8000: {self.dataList[5]}'
        elif (self.dataList[3] == 110):
            return f'Configure Pin {self.dataList[1]} OS PID Reset Integrator and set  Target value {self.uint16(4)}'
        elif (self.dataList[3] == 111):
            if self.isResponse:
                return f'Set pin {self.dataList[1]} PID Last Target value {self.hex4(4)}'
            else:
                return f'Set pin {self.dataList[1]} Request Last Target Value' 
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} Input Process unknown command'

    def configureSWI2C(self):
        if (self.dataList[3] == 0):
            return f'Configure Pin {self.dataList[1]} SWI2C SDA Pin: {self.dataList[4]}   Bytes Per Frame: {self.dataList[5]} Pull Ups: {self.dataList[6]} '
        elif (self.dataList[3] == 1):
            return f'Configure Pin {self.dataList[1]} SWI2C beginTransmission Address: {self.hex2(4)}' 
        elif (self.dataList[3] == 2):
            return f'Configure Pin {self.dataList[1]} SWI2C endTransmission Stop: {self.hex2(4)}' 
        elif (self.dataList[3] == 3):
            return f'Configure Pin {self.dataList[1]} SWI2C writeByte {self.dataList[4]} / {self.hex2(4)}' 
        elif (self.dataList[3] == 4):
            return f'Configure Pin {self.dataList[1]} SWI2C requestFrom Address: {self.hex2(4)} Quantity: {self.dataList[5]} Stop: {self.dataList[6]} iSize: {self.dataList[7]}'
        elif (self.dataList[3] == 5):
            return f'Configure Pin {self.dataList[1]} SWI2C requestFrom iaddress: {self.dec8(4)} / {self.hex8(4)}' 
        elif (self.dataList[3] == 7):
            return f'Configure Pin {self.dataList[1]} SWI2C set Busy: {self.dataList[4]}'
        elif (self.dataList[3] == 8):
            if self.isResponse:
                return f'Configure Pin {self.dataList[1]} SWI2C get Status Busy: {self.dataList[4]}, Bytes Txd: {self.dataList[5]} Bytes Rxd: {self.dataList[6]} NackResult: {self.dataList[7]}'
            else:
                return f'Configure Pin {self.dataList[1]} SWI2C get Status:'
        elif (self.dataList[3] == 9):
            if self.isResponse:
                return f'Configure Pin {self.dataList[1]} SWI2C get rx bytes 0-3: ' +  "".join('{:02X} '.format(x) for x in self.dataList[-4:])
            else:
                return f'Configure Pin {self.dataList[1]} SWI2C get rx bytes 0-3:'
        elif (self.dataList[3] == 10):
            if self.isResponse:
                return f'Configure Pin {self.dataList[1]} SWI2C get rx bytes 4-7: ' +  "".join('{:02X} '.format(x) for x in self.dataList[-4:])
            else:
                return f'Configure Pin {self.dataList[1]} SWI2C get rx bytes 4-7:'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} SWI2C Unknown Packet'

    def setDigitalIO(self):
        if self.dataList[0] == 0xC8:
            stateValue = self.dataList[3]
            if stateValue == 0:
                state = 'Low'
            elif stateValue == 1:
                state = 'High'
            elif stateValue == 2:
                state = 'Input'
            else:
                state = f'Unknown state {stateValue}'

            pullup = self.dataList[4]
            pulldown = self.dataList[5]
            openDrain = self.dataList[6] if self.dataList[6] != 0x55 else self.dataList[7]
            return f'Set pin {self.dataList[1]} Digital {state} - Pull Up {pullup} Pull Down {pulldown} Open Drain {openDrain}'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} Digital IO- Unknown command {self.hex2(0)}'

    def setControlled(self):
            return f'Set pin {self.dataList[1]} Controlled - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setServo(self):
        if self.dataList[0] == 0xC8:
            reverse = self.dataList[6] > 0
            position = self.dataList[4] + self.dataList[5] * 256
            return f'Set pin {self.dataList[1]} Servo- Position: {position} reverse:{reverse} '
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} Servo- fixedTime: {self.dataList[3] + self.dataList[4] * 256} uS, variableTime:{self.dataList[5] + self.dataList[6] * 256} uS'
        elif self.dataList[0] == 0xCB:
            return f'Set pin {self.dataList[1]} Servo- period: {self.uint16(3)} uS'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} Servo- Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setThroughputConsumer(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} Throughput Consumer Reset all to Zero'
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} Throughput Consumer entry {self.dataList[3]} to {self.dataList[4] + self.dataList[5] * 256}'
        elif self.dataList[0] == 0xCA:
            return f'Set pin {self.dataList[1]} Throughput Consumer consume {self.dataList[3] + self.dataList[4] * 256} now'
        else:
            return f'Set pin {self.dataList[1]} Throughput Coonsumer ' 

    def setQuadEnc(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} QuadEnc- debounce count:{self.dataList[3] + self.dataList[4] * 256} 2nd Pin:{self.dataList[5]}  Read State: {self.dataList[6]} Pull Ups Enabled: {self.dataList[7]} '
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} QuadEnc- increment {self.uint16(3)}'
        elif self.dataList[0] == 0xCA:
            return f'Set pin {self.dataList[1]} QuadEnc- minimum {self.uint16(3)} maximum {self.uint16(5)}'
        elif self.dataList[0] == 0xCB:
            return f'Set pin {self.dataList[1]} QuadEnc- public data target pin {self.dataList[3]}'
        elif self.dataList[0] == 0xCC:
            return f'Set pin {self.dataList[1]} QuadEnc- read state every {self.uint16(3)} mS'
        elif self.dataList[0] == 0xCD:
            return f'Set pin {self.dataList[1]} QuadEnc- read state now'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} Quad Enc- Unknown command {self.hex2(0)}'

    def setHBridge(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} HBridge- 2nd Pin:{self.dataList[3]} Driver enum: {self.dataList[4]}'
        elif self.dataList[0] == 0xDC:
            return f'Set pin {self.dataList[1]} HBridge- PWM Period {self.dataList[3] + self.dataList[4] * 256} '
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} HBridge- Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setWatchdog(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} Watchdog: NonTimeout State:{self.dataList[3]}, TimeoutState:{self.dataList[4]}, Timeout (mS): {self.dataList[5] + 256 * self.dataList[6]}, ResetOnTimeout: {self.dataList[7]}    '
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} Watchdog: Use Pin Bitfield: {self.dataList[3]}, PinBitfield:{self.dataList[4]}, Delay in TimeoutState (mS): {self.dataList[5] + 256 * self.dataList[6]}     '

        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} Watchdog - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setInputProcessor(self):
        return f'Set pin {self.dataList[1]} Input Processor, source pin {self.dataList[3]}, default value {self.dataList[4]} '

    def setAnalogInput(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} Analog Input - (Initialization) '
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} Analog Input - Set Total Samples {self.dataList[3] + self.dataList[4] * 256}, filter constant {self.dataList[5] + self.dataList[6] * 256} Public Data Output: {self.dataList[7]} '
        elif self.dataList[0] == 0xCB:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} Analog Input - Min: {self.dataList[3] + self.dataList[4] * 256} Max: {self.dataList[5] + self.dataList[6] * 256}'
            else:
                return f'Set pin {self.dataList[1]} Analog Input - Read Min/Max, Reset MinMax: {self.dataList[3]} '
        elif self.dataList[0] == 0xCC:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} Analog Input - Averaged: {self.dataList[3] + self.dataList[4] * 256} Filtered: {self.dataList[5] + self.dataList[6] * 256}'
            else:
                return f'Set pin {self.dataList[1]} Analog Input - Read Averaged / Filtered '
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} Analog Input - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setResistanceInput(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} Resistance Input - (Initialization) '
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} Resistance Input - Set Total Samples {self.dataList[3] + self.dataList[4] * 256}, filter constant {self.dataList[5] + self.dataList[6] * 256} Public Data Output: {self.dataList[7]} '
        elif self.dataList[0] == 0xCB:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} Resistance Input - Min: {self.dataList[3] + self.dataList[4] * 256} Max: {self.dataList[5] + self.dataList[6] * 256}'
            else:
                return f'Set pin {self.dataList[1]} Resistance Input - Read Min/Max, Reset MinMax: {self.dataList[3]} '
        elif self.dataList[0] == 0xCC:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} Resistance Input - Averaged: {self.dataList[3] + self.dataList[4] * 256} Filtered: {self.dataList[5] + self.dataList[6] * 256}'
            else:
                return f'Set pin {self.dataList[1]} Resistance Input - Read Averaged / Filtered '
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} Resistance Input - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setPulseOnChange(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} PulseOnChange active mode: {self.dataList[3]} Inactive mode {self.dataList[4]} orNotAnd: {self.dataList[5]}'
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} PulseOnChange ontime:{self.dataList[3] + self.dataList[4] * 256} offtime: {self.dataList[5] + self.dataList[6] * 256} '
        elif self.dataList[0] == 0xCA:
            return f'Set pin {self.dataList[1]} PulseOnChange pwmPeriod:{self.dataList[3] + self.dataList[4] * 256} pwmDuty: {self.dataList[5] + self.dataList[6] * 256} '
        elif self.dataList[0] == 0xCB:
            return f'Set pin {self.dataList[1]} PulseOnChange configure entry {self.dataList[3]} value0: {self.dataList[4] + self.dataList[5] * 256} value1: {self.dataList[6] + self.dataList[7] * 256} '
        elif self.dataList[0] == 0xCC:
            return f'Set pin {self.dataList[1]} PulseOnChange configure entry {self.dataList[3]} mode: {self.dataList[4]} sourcePin: {self.dataList[5]}' 
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} PulseOnChange - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setHFServo(self):
        if self.dataList[0] == 0xC8:
            reverse = self.dataList[6] > 0
            position = self.dataList[4] + self.dataList[5] * 256
            return f'Set pin {self.dataList[1]} HF Servo- Position: {position} reverse:{reverse} '
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} HF Servo- fixedTime: {self.dataList[3] + self.dataList[4] * 256} uS, variableTime:{self.dataList[5] + self.dataList[6] * 256} uS'
        elif self.dataList[0] == 0xCB:
            return f'Set pin {self.dataList[1]} HF Servo- period: {self.dataList[3] + self.dataList[4] * 256} uS'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} HF Servo- Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '


    def setVGA(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} VGA:  Buffer Address:  {self.hex4(5)}'
        elif self.dataList[0] == 0xC9:
            if self.dataList[3] == 0:
                return f'Set pin {self.dataList[1]} VGA set Pixel ({self.dataList[4]},{self.dataList[5]}) to color {self.dataList[6]}' 
            if self.dataList[3] == 1:
                return f'Set pin {self.dataList[1]} VGA Fill Screen color {self.dataList[4]}' 
            if self.dataList[3] == 2:
                return f'Set pin {self.dataList[1]} VGA Fill Rect  ({self.dataList[4]},{self.dataList[5]}) to ({self.dataList[6]},{self.dataList[7]})' 
            if self.dataList[3] == 3:
                return f'Set pin {self.dataList[1]} VGA Clear Rect ({self.dataList[4]},{self.dataList[5]}) to ({self.dataList[6]},{self.dataList[7]})' 
            else:
                self.unknown();
                return f'Set pin {self.dataList[1]} VGA - Unknown C9 command {"".join("{:02X} ".format(self.dataList[3]))} '
        elif self.dataList[0] == 0xCA:
            return f'Set pin {self.dataList[1]} VGA line {self.dataList[3]} to {self.dataList[4]} to color {self.dataList[5]}' 
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} VGA - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setPS2Keyboard(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} PS/2 Keyboard: Data pin {self.dataList[3]} Queue mode {self.dataList[4]} Buffer mode {self.dataList[5]} PullUpDown {self.dataList[7]}'
        elif self.dataList[0] == 0xCE:
            return f'Set pin {self.dataList[1]} PS/2 Keyboard: Queue address {self.hex4(3)}'
        elif self.dataList[0] == 0xC9:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} PS/2 Keyboard: {self.dataList[4]} bytes available'
            else:
                return f'Set pin {self.dataList[1]} PS/2 Keyboard: Available request'
        elif self.dataList[0] == 0xCA:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} PS/2 Keyboard: Read {self.dataList[3]} bytes: {self.bytesToHex(4,4 + min(self.dataList[3],4))}'
            else:
                return f'Set pin {self.dataList[1]} PS/2 Keyboard: Read up to {self.dataList[3]} bytes'
        elif self.dataList[0] == 0xCB:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} PS/2 Keyboard: Peek, available {self.dataList[4]} first value {self.hex2(5)}'
            else:
                return f'Set pin {self.dataList[1]} PS/2 Keyboard: Peek request'
        elif self.dataList[0] == 0xCF:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} PS/2 Keyboard: Current scan codes {self.bytesToHex(3,8)}'
            else:
                return f'Set pin {self.dataList[1]} PS/2 Keyboard: Read current scan codes starting at {self.dataList[3]}'
        else:
            self.unknown()
            return f'Set pin {self.dataList[1]} PS/2 Keyboard - Unknown command {self.hex2(0)}'

    def setFrequencyOutput(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} Frequency Output: Duty {self.uint16(3)} Max frequency {self.uint16(5)} Hz Low frequency mode {self.dataList[7]}'
        else:
            self.unknown()
            return f'Set pin {self.dataList[1]} Frequency Output - Unknown command {self.hex2(0)}'

    def setBlink(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} Blink: Public data source {self.dataList[3]}'
        else:
            self.unknown()
            return f'Set pin {self.dataList[1]} Blink - Unknown command {self.hex2(0)}'

    def setRandomBlink(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} Random Blink: On time max {self.uint16(3)} mS Off time max {self.uint16(5)} mS'
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} Random Blink: On PWM min {self.uint16(3)} On PWM max {self.uint16(5)}'
        elif self.dataList[0] == 0xCA:
            return f'Set pin {self.dataList[1]} Random Blink: Off PWM min {self.uint16(3)} Off PWM max {self.uint16(5)}'
        elif self.dataList[0] == 0xCB:
            return f'Set pin {self.dataList[1]} Random Blink: On time min {self.uint16(3)} mS Off time min {self.uint16(5)} mS'
        else:
            self.unknown()
            return f'Set pin {self.dataList[1]} Random Blink - Unknown command {self.hex2(0)}'

    def setCharlieplex(self):
        """Decode PIN_MODE_CHARLIEPLEX (43) configuration commands."""

        command = self.dataList[0]
        pin = self.dataList[1]

        if command == 0xC8:
            displayModeNames = {
                0: 'Bitmap',
                1: 'Public data 16-bit bitmap',
                2: 'Scaled single LED',
                3: 'Scaled bargraph'
            }
            displayMode = self.dataList[4]
            displayModeName = displayModeNames.get(
                displayMode, f'Unknown display mode {displayMode}')
            logicalPin2 = ('Unused' if self.dataList[7] == 0xFF
                           else str(self.dataList[7]))
            return (
                f'Set pin {pin} Charlieplex initialization: '
                f'Number of pins {self.dataList[3]}, '
                f'Display mode {displayMode} ({displayModeName}), '
                f'Scan period {self.dataList[5]} mS, '
                f'Physical pin for logical pin 1 / lookup storage pin {self.dataList[6]}, '
                f'Physical pin for logical pin 2 {logicalPin2}'
            )

        elif command == 0xC9:
            pinDescriptions = []
            for logicalPin, physicalPin in enumerate(self.dataList[3:8], start=3):
                if physicalPin == 0xFF:
                    pinDescriptions.append(f'P{logicalPin}=Unused')
                else:
                    pinDescriptions.append(f'P{logicalPin}={physicalPin}')
            return (
                f'Set pin {pin} Charlieplex logical pins 3-7: ' +
                ', '.join(pinDescriptions)
            )

        elif command == 0xCA:
            return (
                f'Set pin {pin} Charlieplex bitmap LEDs 0-39: '
                f'{self.hex2(3)}{self.hex2(4)}{self.hex2(5)}'
                f'{self.hex2(6)}{self.hex2(7)}'
            )

        elif command == 0xCB:
            return (
                f'Set pin {pin} Charlieplex bitmap LEDs 40-55: '
                f'{self.hex2(3)}{self.hex2(4)}'
            )

        elif command == 0xCC:
            firstLED = self.dataList[3]
            mappings = []
            for offset, encodedPins in enumerate(self.dataList[4:8]):
                logicalLED = firstLED + offset
                highPin = (encodedPins >> 4) & 0x0F
                lowPin = encodedPins & 0x0F
                mappings.append(
                    f'LED {logicalLED}: P{highPin} high/P{lowPin} low '
                    f'(0x{encodedPins:02X})'
                )
            return (
                f'Set pin {pin} Charlieplex lookup entries: ' +
                ', '.join(mappings)
            )

        elif command == 0xCD:
            ledIndexes = [
                value for value in self.dataList[3:8]
                if value != 0xFF
            ]
            if len(ledIndexes) == 0:
                ledText = 'none'
            else:
                ledText = ', '.join(str(value) for value in ledIndexes)
            return f'Set pin {pin} Charlieplex set LEDs: {ledText}'

        elif command == 0xCE:
            ledIndexes = [
                value for value in self.dataList[3:8]
                if value != 0xFF
            ]
            if len(ledIndexes) == 0:
                ledText = 'none'
            else:
                ledText = ', '.join(str(value) for value in ledIndexes)
            return f'Set pin {pin} Charlieplex clear LEDs: {ledText}'

        else:
            self.unknown()
            return (
                f'Set pin {pin} Charlieplex - Unknown command '
                f'{self.hex2(0)} Data: {self.bytesToHex(3,8)}'
            )

    def setSPI(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} SPI: Mode {self.dataList[3]} MOSI {self.dataList[4]} MISO {self.dataList[5]} CS {self.dataList[6]}'
        elif self.dataList[0] == 0xC9 or self.dataList[0] == 0xCA:
            stayLow = 'CS stay low' if self.dataList[0] == 0xCA else 'CS release'
            if self.isResponse:
                byteCount = (self.dataList[3] + 7) // 8
                return f'Set pin {self.dataList[1]} SPI Transfer {self.dataList[3]} bits ({stayLow}) RX: {self.bytesToHex(4,4 + min(byteCount,4))}'
            else:
                byteCount = (self.dataList[3] + 7) // 8
                return f'Set pin {self.dataList[1]} SPI Transfer {self.dataList[3]} bits ({stayLow}) TX: {self.bytesToHex(4,4 + min(byteCount,4))}'
        elif self.dataList[0] == 0xCB or self.dataList[0] == 0xCC:
            stayLow = 'CS stay low' if self.dataList[0] == 0xCC else 'CS release'
            if self.isResponse:
                return f'Set pin {self.dataList[1]} SPI Transfer 40 bits ({stayLow}) RX: {self.bytesToHex(3,8)}'
            else:
                return f'Set pin {self.dataList[1]} SPI Transfer 40 bits ({stayLow}) TX: {self.bytesToHex(3,8)}'
        elif self.dataList[0] == 0xCD:
            return f'Set pin {self.dataList[1]} SPI Set CS High'
        else:
            self.unknown()
            return f'Set pin {self.dataList[1]} SPI - Unknown command {self.hex2(0)}'

    def setI2CController(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} I2CController - SDA Pin: {self.dataList[3]} Bytes Per Frame: {self.dataList[4]} Pull Ups: {self.dataList[5]}'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} I2CController - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '


    def setQueuedPulseOutput(self):
        if self.dataList[0] == 0xC8:
            if ( self.dataList[5] > 0):
                units = 'mS'
            else:
                units = 'uS'
            return f'Set pin {self.dataList[1]} Queued Pulse Output - Initial State: {self.dataList[3]} Idle State: {self.dataList[4]} Units: {units}  Queue Address: {self.hex4(6)}'
        elif self.dataList[0] == 0xC9:
            if (self.isResponse):
                return f'Set pin {self.dataList[1]} Queued Pulse Output - Queue result code:  {self.dataList[3]} items in queue: {self.dec4(4)} Free items in queue: {self.dec4(6)}'
            else:
                if (self.dataList[4] >= 128):
                    item1 = 'High'
                else:
                    item1 = 'Low '
                if (self.dataList[6] >= 128):
                    item2 = 'High'
                else:
                    item2 = 'Low'
                return f'Set pin {self.dataList[1]} Queued Pulse Output - Queue {item1} {self.dataList[3] + (self.dataList[4] & 0x7F) * 256}, queue {item2} {self.dataList[5] + (self.dataList[6] & 0x7F) * 256} Empty Queue First: {self.dataList[7]}'
        elif self.dataList[0] == 0xCA:
            return f'Set pin {self.dataList[1]} Queued Pulse Output - Paused: {self.dataList[3]}'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} Queued Pulse Output- Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '


    def setIRRx(self):
        if self.dataList[0] == 0xC8:
            if ( self.dataList[4] > 0):
                repeat = 'UseRepeat'
            else:
                repeat = 'DontUseRepeat'
            if self.dataList[5] == 0:
                ll = 'Low'
            else:
                ll = 'High'
            return f'Set pin {self.dataList[1]} IR Rx: mode:{self.dataList[3]}  {repeat} Active: {ll}  Address Filter: {self.hex4(6)}'
        elif self.dataList[0] == 0xC9:
            if ( self.dataList[7] > 0):
                af = 'UseAddressFilter'
            else:
                af = 'DontUseAddressFilter'
            return f'Set pin {self.dataList[1]} IR Rx: Timeout Per: {self.hex4(3)}  Timeout Val: {self.hex4(5)} {af}'
        elif self.dataList[0] == 0xCA:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} IRRX - Read data: Read {self.dataList[3]} bytes:{"".join("{:02x} ".format(x) for x in self.dataList[4:4 + self.dataList[3]])} '
            else:
                return f'Set pin {self.dataList[1]} IRRX - Read data: Read up to {self.dataList[3]} bytes'
        elif self.dataList[0] == 0xCB:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} IRRX - Peek data: {self.dataList[4]} bytes available, first data {self.hex2(5)}'
            else:
                return f'Set pin {self.dataList[1]} IRRX - Peek data'
        elif self.dataList[0] == 0xCC:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} IRRX - Last Address {self.hex4(3)} Data Count {self.uint16(5)}'
            else:
                return f'Set pin {self.dataList[1]} IRRX - Read last address and data count'
        elif self.dataList[0] == 0xCD:
            return f'Set pin {self.dataList[1]} IRRX - Public data output mode {self.dataList[3]}'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} IR Rx: Unknown command {self.hex2(0)}'

    def setIRTx(self):
        if self.dataList[0] == 0xC8:
            irMode = self.dataList[3]
            return f'Set pin {self.dataList[1]} IR Tx: mode:{self.dataList[3]}'
        elif self.dataList[0] == 0xC9:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} IRTX - Tx bytes Free:  {self.dataList[3]}  '
            else:
                return f'Set pin {self.dataList[1]} IRTX - Tx addr {self.hex4(4)} cmd {self.dataList[6]} repeat {self.dataList[7]}'
        elif self.dataList[0] == 0xCB:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} IRTX - Tx Free: Read {self.dataList[3]}  '
            else:
                return f'Set pin {self.dataList[1]} IRTX - Peek'
        elif self.dataList[0] == 220:
                return f'Set pin {self.dataList[1]} IRTX - Enable SW8B 38kHz carrier '
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} IR Rx: Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '


    def setProtectedOutput(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} Protected Output - Expected Value {self.dataList[3] + 256 * self.dataList[4]} Debounce time: {self.dataList[5]} monitorPin: {self.dataList[6]} Safe State: {self.dataList[7]}'
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} Protected Output - Match Method: {self.dataList[3]} Active State: {self.dataList[4]}'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} Protected Output - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setDebounce(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} Debounce:  Pull ups: {self.dataList[7]}, period (mS):{self.dataList[3]},  invert: {self.dataList[5]} '
        if self.dataList[0] == 0xC9:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} Debounce:  Level: {self.dataList[3]}, transitions:{self.dataList[4] + self.dataList[5] * 256}  Stable mS:  {self.dataList[6] + self.dataList[7] * 256}'
            else:
                return f'Set pin {self.dataList[1]} Debounce:  Request data'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} Debounced Inp. - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '


    def setTM1637(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} TM1637: DIO Pin:{self.dataList[3]}, Digits: {self.dataList[4]}  Mode: {self.dataList[5]} Source: {self.dataList[6]} Bright: {self.dataList[7]}'
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} TM1637: Map 0 dig:{self.dataList[3]}, Map 1 dig: {self.dataList[4]}  Map 2 dig: {self.dataList[5]} Map 3 dig: {self.dataList[6]} Map 4 dig: {self.dataList[7]}'
        elif self.dataList[0] == 0xCA:
            return f'Set pin {self.dataList[1]} TM1637: Map 5 dig:{self.dataList[3]}'
        elif self.dataList[0] == 0xCB:
            if self.dataList[3] == 0x55 and self.dataList[4] != 0x55:
                return f'Set pin {self.dataList[1]} TM1637: Suppress leading zeros:{self.dataList[4]}'
            return f'Set pin {self.dataList[1]} TM1637: Brightness:{self.dataList[3]}'
        elif self.dataList[0] == 0xCC:
            return f'Set pin {self.dataList[1]} TM1637: Output 0:{self.dataList[3]}, Output 1:{self.dataList[4]}, Output 2:{self.dataList[5]}, Output 3:{self.dataList[6]}, Output 4:{self.dataList[7]}'
        elif self.dataList[0] == 0xCD:
            return f'Set pin {self.dataList[1]} TM1637: Output 5:{self.dataList[3]}'
        elif self.dataList[0] == 0xCE:
            return f'Set pin {self.dataList[1]} TM1637: Decimal bitmap:{self.dataList[3]}'
        elif self.dataList[0] == 0xCF:
            return f'Set pin {self.dataList[1]} TM1637: Blink bitmap:{self.dataList[3]}'
        elif self.dataList[0] == 0xD0:
            count = self.dataList[3]
            return f'Set pin {self.dataList[1]} TM1637: Write {count} character(s): ' + ''.join(chr(x) if 32 <= x <= 126 else f'\\x{x:02X}' for x in self.dataList[4:4 + min(count,4)])
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} TM1637 - Unknown command {self.hex2(0)}'

    def setWS2812(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} WS2812: Buff indx: {self.hex4(3)}, #LEDs:{self.dataList[5]}'
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} WS2812: Set LED:{self.dataList[3]} Blue: {self.hex2(4)} Green: {self.hex2(5)} Red: {self.hex2(6)}'
        elif self.dataList[0] == 0xCA:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} WS2812:  Bytes Required: {self.dataList[3] + self.dataList[4] * 256}'
            else:
                return f'Set pin {self.dataList[1]} WS2812:  Request bytes required for {self.dataList[3]} LEDs'
        elif self.dataList[0] == 0xCB:
            return f'Set pin {self.dataList[1]} WS2812: Set Frame:{self.dataList[3]} LED:{self.dataList[4]} Blue: {self.hex2(5)} Green: {self.hex2(6)} Red: {self.hex2(7)}'
        elif self.dataList[0] == 0xCC:
            return f'Set pin {self.dataList[1]} WS2812: Anim indx: {self.hex4(3)}, #Frames:{self.dataList[5]}'
        elif self.dataList[0] == 0xCD:
            return f'Set pin {self.dataList[1]} WS2812: Anim delay frame:{self.dataList[3]} to {self.dataList[4] + self.dataList[5]*256} mS'
        elif self.dataList[0] == 0xCE:
            if self.dataList[3] == 0:
                return f'Set pin {self.dataList[1]} WS2812: Mode Buffered RGB' 
            elif self.dataList[3] == 1:
                return f'Set pin {self.dataList[1]} WS2812: Mode Animation' 
            elif self.dataList[3] == 2:
                return f'Set pin {self.dataList[1]} WS2812: Mode Chase' 
            elif self.dataList[3] == 3:
                return f'Set pin {self.dataList[1]} WS2812: Mode Bar Graph Source {self.dataList[4]}' 
            else:
                self.unknown();
                return f'Set pin {self.dataList[1]} WS2812: Mode UNKNOWN' 
        elif self.dataList[0] == 0xCF:
            return f'Set pin {self.dataList[1]} WS2812: Bar graph min {self.uint16(3)} max {self.uint16(5)}'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} WS2812 - Unknown command {self.hex2(0)}'



    def setMatrixKeypad(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} Matrix Keypad r0: {self.dataList[3]} r1: {self.dataList[4]} r2: {self.dataList[5]} r3: {self.dataList[6]} c0: {self.dataList[7]} '
        elif self.dataList[0] == 0xC9:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} Matrix Keypad- Available: {self.dataList[4]} bytes'
            else:
                return f'Set pin {self.dataList[1]} Matrix Keypad- Available request'
        elif self.dataList[0] == 0xCA:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} Matrix Keypad- Read data: Read {self.dataList[3]} bytes:{"".join("{:02x} ".format(x) for x in self.dataList[4:4 + self.dataList[3]])} '
            else:
                return f'Set pin {self.dataList[1]} Matrix Keypad- Read data: up to {self.dataList[3]} bytes'

        elif self.dataList[0] == 0xCB:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} Matrix Keypad- Peek data:   {self.dataList[3]} bytes rx available, 1st available data value: {hex(self.dataList[5])}'
            else:
                return f'Set pin {self.dataList[1]} Matrix Keypad- Peek data'
        if self.dataList[0] == 0xCD:
            return f'Set pin {self.dataList[1]} Matrix Keypad c1: {self.dataList[3]} c2: {self.dataList[4]} c3: {self.dataList[5]} buf mode: {self.dataList[6]} queue mode: {self.dataList[7]} '
        if self.dataList[0] == 0xCE:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} Matrix Keypad Get info Pressed: {self.dataList[3]} Changecount:{self.dataList[4] + self.dataList[5] * 256} Current held time: {self.dataList[6] + self.dataList[7] * 256}'
            else:
                return f'Set pin {self.dataList[1]} Matrix Keypad Get info for key Index {self.dataList[4]}  Reset count: {self.dataList[3]}'
        if self.dataList[0] == 0xCF:
            return f'Set pin {self.dataList[1]} Matrix Keypad set queueMask {self.hex2(3)}'
        if self.dataList[0] == 0xD0:
            return f'Set pin {self.dataList[1]} Matrix Keypad set row timing {self.dataList[3]}'
        if self.dataList[0] == 0xD1:
            return f'Set pin {self.dataList[1]} Matrix Keypad ASCII table index {self.dataList[3]} value {self.hex2(4)}'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} Matrix Keypad - Unknown command {self.hex2(0)} '

    def setPWM(self):
        if self.dataList[0] == 0xC8:
            counts = self.dataList[4] + self.dataList[5] * 256;
            return f'Set pin {self.dataList[1]} PWM- Duty Cycle: {counts}/65535, {counts * 100 / 65535}%  Invert: {self.dataList[6]}'
        elif self.dataList[0] == 0xDC:
            return f'Set pin {self.dataList[1]} PWM- period {self.dec8(3)} uS'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} PWM - Unknown command {self.hex2(0)} '


    def setUARTTXRX(self):
        swUart = "HW1"
        if self.dataList[2] == 23:
            swUart = "HW2"
        if self.dataList[2] == 13:
            swUart = " SW";
        if self.dataList[0] == 0xC8:
            baudList = [ 300,  1200, 2400,  4800,  9600,  19200,  38400,  57600 , 115200 ]
            if self.dataList[3] <= 8:
                baud = baudList[self.dataList[3]]
            else:
                baud = 115200

            outstr = f'Set pin {self.dataList[1]}'
            if self.dataList[2] == 13:  #software uart
                outstr = outstr + swUart
            return outstr + f' UART- Baud: {baud}, Rx Pin: {self.dataList[4]}, Tx Pin {self.dataList[5]}'

        elif self.dataList[0] == 0xC9:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} {swUart} UART- Transmit data: {self.dataList[3]} bytes tx buffer available, {self.dataList[4]} bytes available for RX'
            else:
                return f'Set pin {self.dataList[1]} {swUart} UART- Transmit data: {"".join("{:02x}".format(x) for x in self.dataList[4:4 + self.dataList[3]])}'
        elif self.dataList[0] == 0xCA:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} {swUart} UART- Read data: Read {self.dataList[3]} bytes:{"".join("{:02x} ".format(x) for x in self.dataList[4:4 + self.dataList[3]])} '
            else:
                return f'Set pin {self.dataList[1]} {swUart} UART- Read data: up to {self.dataList[3]} bytes'

        elif self.dataList[0] == 0xCB:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} {swUart} UART- Peek data:  {self.dataList[3]} bytes tx buffer available, {self.dataList[3]} bytes rx available, 1st available data value: {hex(self.dataList[5])}'
            else:
                return f'Set pin {self.dataList[1]} {swUart} UART- Peek data'
        elif self.dataList[0] == 0xCC:
            return f'Set pin {self.dataList[1]} {swUart} UART- Close Port'
        elif self.dataList[0] == 0xCD:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} {swUart} UART- Bytes free in Tx queue  {self.dataList[5] + self.dataList[6] * 256} bytes' 
            else:
                return f'Set pin {self.dataList[1]} {swUart} UART- Set TX queue Index {self.dataList[3] + 256 * self.dataList[4]}'
        elif self.dataList[0] == 0xCE:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} {swUart} UART- Bytes free in Rx queue  {self.dataList[5] + self.dataList[6] * 256} bytes' 
            else:
                return f'Set pin {self.dataList[1]} {swUart} UART- Set RX queue Index {self.dataList[3] + 256 * self.dataList[4]}'
            
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} UARTTXRX - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '


    def setPulseTimer(self):
        if self.dataList[0] == 0xC8:
            if (self.dataList[4] == 0):
                units = "uS"
            else:
                units = "mS"
            if (self.dataList[3] == 0):
                pullUps = "Pull Ups Disabled"
            else:
                pullUps = "Pull Ups Enabled"
            return f'Set pin {self.dataList[1]} Pulse Timer- {pullUps} units {units}  '
        elif self.dataList[0] == 0xC9:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} Pulse Timer- High time: {self.dataList[3] + self.dataList[4] * 256}  Low time: {self.dataList[5] + self.dataList[6] * 256} Count LSB: {self.dataList[7]}'
            else:
               return f'Set pin {self.dataList[1]} Pulse Timer- Read High Time and Low Time'
        elif self.dataList[0] == 0xCA:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} Pulse Timer- High time: {self.dataList[3] + self.dataList[4] * 256}  Count: {self.dataList[5] + self.dataList[6] * 256} Overflow: {self.dataList[7]}'
            else:
                return f'Set pin {self.dataList[1]} Pulse Timer- Read High Time and Low Time'
        elif self.dataList[0] == 0xCB:
            return f'Set pin {self.dataList[1]} Pulse Timer- Public Data Output: {self.dataList[3]}'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} Pulse Timer - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setFrameTimer(self):
       return f'Set pin {self.dataList[1]} to frame timer' 

    def setCapTouch18(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} CapTouch18- Charge Counts:{self.uint16(3)} Delay: {self.uint16(5)}  '
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} CapTouch18- Dig Low Limit:{self.dataList[3] + self.dataList[4] * 256}  Dig High Limit:{self.dataList[5] + self.dataList[6] * 256}'
        elif self.dataList[0] == 0xCA:
            return f'Set pin {self.dataList[1]} CapTouch18- Dig Low Value:{self.dataList[3] + self.dataList[4] * 256}  Dig High Value:{self.dataList[5] + self.dataList[6] * 256}'
        elif self.dataList[0] == 0xCB:
            return f'Set pin {self.dataList[1]} CapTouch18- DigEnable: {self.dataList[3]} Invert: {self.dataList[4]} Debounce: {self.dataList[5] + self.dataList[6] * 256} '
        elif self.dataList[0] == 0xCC:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} CapTouch Timer- Current State: {self.dataList[3]}  Transitions: {self.dataList[4] + self.dataList[5] * 256}  Time: {self.dataList[6] + self.dataList[7] * 256}'
            else:
                return f'Set pin {self.dataList[1]} CapTouch Request Digital - Reset Trans: {self.dataList[3]}'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} CapTouch18 - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setUltrasonicDistanceSensor(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} Ultrasonic Distance Sensor- Driver: {self.dataList[3]} Trig Pin: {self.dataList[4]} Pull up: {self.dataList[5]} AutoTrigger: {self.dataList[6]}  '
        elif self.dataList[0] == 0xC9:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} Ultrasonic Distance Sensor - Distance: {self.dataList[3] + self.dataList[4] * 256} mm   Pulse Count: {self.dataList[5] + self.dataList[6] * 256} '
            else:
               return f'Set pin {self.dataList[1]} UltraSonic Distance sensor  Manual Trigger: {self.dataList[3]}' 
        elif self.dataList[0] == 0xCA:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} Ultrasonic Distance Sensor - Distance: {self.dataList[3] + self.dataList[4] * 256} mm   Pulse Count: {self.dataList[5] + self.dataList[6] * 256} '
            else:
               return f'Set pin {self.dataList[1]} UltraSonic Distance sensor  Request Distance and Pulse Count' 
        elif self.dataList[0] == 0xCB:
            return f'Set pin {self.dataList[1]} Ultrasonic Distance Sensor - Servo pin {self.dataList[3]} Mem Index: {self.hex4(4)} Positions: {self.dataList[6] + self.dataList[7] * 256} '
        elif self.dataList[0] == 0xCC:
            return f'Set pin {self.dataList[1]} Ultrasonic Distance Sensor - Servo increment: {self.dataList[3] + self.dataList[4] * 256} Reverse: {self.dataList[7]} '
        elif self.dataList[0] == 0xCD:
            return f'Set pin {self.dataList[1]} Ultrasonic Distance Sensor - Move delay: {self.dataList[3] + self.dataList[4] * 256} Return Delay: {self.dataList[5] + self.dataList[6] * 256} '
        elif self.dataList[0] == 0xCE:
            return f'Set pin {self.dataList[1]} Ultrasonic Distance Sensor - Sweep Enable: {self.dataList[3]}'
        self.unknown();
        return 'Unknown Ultrasonic Distance Sensor Packet'

    def setLiquidCrystal(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} Liquid Crystal RS: {self.dataList[3]} D4: {self.dataList[4]} D5: {self.dataList[5]} D6: {self.dataList[6]} D7: {self.dataList[7]} '
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} Clock in - Address : {self.dataList[3]} Data: {self.dataList[4]} Data: {self.dataList[5]} Data: {self.dataList[6]} Data: {self.dataList[7]} '
        elif self.dataList[0] == 0xCA:
            return f'Set pin {self.dataList[1]} Set CGRAM - Address : {self.dataList[3]} Data: {self.dataList[4]} Data: {self.dataList[5]} Data: {self.dataList[6]} Data: {self.dataList[7]} '
        elif self.dataList[0] == 0xCB:
            return f'Set pin {self.dataList[1]} Configure Display Control / Mode : {self.dataList[3]} And Mask: {self.dataList[4]} Or Mask: {self.dataList[5]} '
        elif self.dataList[0] == 0xCC:
            return f'Set pin {self.dataList[1]} Clock first Command/Data  : {self.dataList[3]} Value: {self.dataList[4]}  second Command/Data  : {self.dataList[5]} Value: {self.dataList[6]} '
        elif self.dataList[0] == 0xCD:
            return f'Set pin {self.dataList[1]} Clock Five Data  : {self.hex2(3)} {self.hex2(4)} {self.hex2(5)} {self.hex2(6)} {self.hex2(7)}'
        elif self.dataList[0] == 0xCE:
            return f'Set pin {self.dataList[1]} Set User Buffer index  : {self.hex4(3)}  Width: {self.dataList[5]} ' 
        elif self.dataList[0] == 0xCF:
            return f'Set pin {self.dataList[1]} Set E2 Pin  :  {self.dataList[3]} ' 
        elif self.dataList[0] == 0xD0:
            return f'Set pin {self.dataList[1]} Set LCD Row Index  {self.dataList[3]}  set to {self.hex(4)}' 
        self.unknown();
        return "Unknown Liquid Crystal Packet"


    def setHSClock(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} HS Clock: Frequency {self.hex8(3)}'
        self.unknown();
        return "Unknown HS Clock Packet"

    def setHSCounter(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} HS Counter: Sample Frames {self.hex4(3)} Public Output Divisor: {self.hex4(5)}  Public Output type: {self.dataList[7]} '
        elif self.dataList[0] == 0xC9:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} HS Counter Read Counter: {self.dec8(3)}  '
            else:
                return f'Set pin {self.dataList[1]} HS Counter Read Counter.   Reset After Read: {self.dataList[3]} '
        elif self.dataList[0] == 0xCA:
            if self.isResponse:
                return f'Set pin {self.dataList[1]} HS Counter Read Frequency: {self.dec8(3)}  '
            else:
                return f'Set pin {self.dataList[1]} HS Counter Read Frequency.  '
        self.unknown();
        return "Unknown HS Counter Packet"

    def queueInit(self):
        if self.isResponse:
            if (self.dataList[3] + 256 * self.dataList[4]) > 0:
                return f'Queue Init address {self.hex4(1)}, Actual Length {self.hex4(3)} Type {self.dataList[5]} '
            else:
                return f'Queue Init creation error {self.dataList[5]}'
        else:
            return f'Queue Init address {self.hex4(1)}, Length {self.hex4(3)} Type {self.dataList[5]} '

    def queueAdd(self):
        count =self.dataList[3]
        if self.isResponse:
            return f'Add to Queue.  {self.uint8(3)} added.  Code: {self.uint8(4)}  Free bytes: {self.uint16(5)}'
        else:
            return f'Add to Queue Addr: {self.hex4(1)} count: {count} {"".join("{:02x} ".format(x) for x in self.dataList[4:4 + count])} '

    def queueAdd7(self):
        count =self.dataList[3]
        if self.isResponse:
            return f'Add 7 bytes to Queue prev addr    {self.uint8(3)} added.  Code: {self.uint8(4)}  Free bytes: {self.uint16(5)}'
        else:
            return f'Add 7 bytes to Queue prev addr   {"".join("{:02x} ".format(x) for x in self.dataList[1:8])} '

    def queueRead(self):
        if self.isResponse:
            count =self.dataList[1]
            return f'Read Queue.  Count: {self.uint8(1)}   {"".join("{:02x} ".format(x) for x in self.dataList[2:2 + count])} '
        else:
            count =self.dataList[3]
            return f'Read Queue Addr: {self.hex4(1)}  '

    def queueInfo(self):
        count =self.dataList[3]
        if self.isResponse:
            return f'Queue Info. Addr: {self.hex4(1)} Peek: {self.hex2(3)} Filled: {self.uint16(4)} Empty: {self.uint16(6)}' 
        else:
            return f'Queue Info Addr: {self.hex4(1)} '

    def queueClone(self):
        count =self.dataList[3]
        if self.isResponse:
            return f'Clone Queue Info. Addr: {self.hex4(1)} Peek: {self.hex2(3)} Filled: {self.uint16(4)} Empty: {self.uint16(6)}' 
        else:
            return f'Clone Queue Addr: {self.hex4(1)}  Copy Addr: {self.hex4(3)} '
