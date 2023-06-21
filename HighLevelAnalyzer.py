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
            if (self.address_byte >= 0x68 and self.address_byte <= 0x6F):
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
        elif self.dataList[0] == 0x42:
            outstr = outstr + self.bootload()
        elif self.dataList[0] == 0x45:
            outstr = outstr + self.error()
        elif self.dataList[0] == 0x52:
            outstr = outstr + self.reset()
        elif self.dataList[0] == 0x53:
            outstr = outstr + self.sleep()
        elif self.dataList[0] == 0x56:
            outstr = outstr + self.version()
        elif self.dataList[0] == 0x5E:
            outstr = outstr + self.lineBreak()
        elif self.dataList[0] == 0x64:
            outstr = outstr + self.asciiSetData()
        elif self.dataList[0] == 0x67:
            outstr = outstr + self.asciiGetData()
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
        elif  self.dataList[0] == 0xA0:
            outstr = outstr + self.readRam() 
        elif  self.dataList[0] == 0xA1:
            outstr = outstr + self.readFlash() 
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
        elif self.dataList[0] == 0xD2: #Output Scaling generic
            outstr = outstr + self.configureOutputScaling() 
        elif self.dataList[0] == 0xD3: #input processor generic
            outstr = outstr + self.configureInputProcessor() 
        elif (self.dataList[0] >= 0xC8 and self.dataList[0] <= 0xDA):
            outstr = outstr + self.configurePin() 


        self.wombat_frame.data["data"] = outstr

    def echo(self):
        outstr = "Echo: "
        outstr =  outstr +  "".join('{:02X} '.format(x) for x in self.dataList[-7:])
        return outstr
    def bootload(self):
        outstr = "Bootload "
        bootStr =  "".join(chr(x) for x in self.dataList)
        if ( bootStr != "BoOtLoAd"):
            outstr += " ERROR! Wrong String " + bootStr;
        return outstr

    errorStrings = [
   'SW_ERROR_UNNUMBERED_ERROR' , # = 32767,
    'SW_ERROR_PINS_MUST_BE_ON_SAME_PORT' , # = 1, ///< Pins must be on the same microcontroller part (e.g. PORTA, PORTB, etc.).  See datasheet of micro for port assignments.
    'SW_ERROR_ASCII_NUMBER_TOO_BIG_16' , # = 2, ///<A number bigger than 65535 was provided to convert to a 16 bit value
            'SW_ERROR_UNKNOWN_PIN_MODE' , # = 3, ///< A Pin mode was indicated that is not avaialble on this model or version of Serial Wombat chip
            'SW_ERROR_RESET_STRING_INCORRECT' , # = 4, ///<A Packet starting with 'R' was received but didn't have the correct following bytes to cause a reset
            'SW_ERROR_INVALID_COMMAND' , # = 5, ///< The first byte of a received packet does not correspond with a command supported by this model of Serial Wombat chip
            'SW_ERROR_INSUFFICIENT_SPACE' , # = 6,  ///< There was not sufficient space in the queue or user area to complete the command.
            'SW_ERROR_WUB_COUNT_GT_4' , # = 7, ///< A count greater than 4 was provided as a number of bytes to write to count user buffer
            'SW_ERROR_WUB_INVALID_ADDRESS' , # = 8, ///<An attempt to write to a user buffer address outside the user buffer was attempted.
            'SW_ERROR_WUB_CONTINUE_OUTOFBOUNDS' , # = 9, ///<  A call to Write User Buffer Continue would have written out of bounds.
            'SW_ERROR_RF_ODD_ADDRESS' , # = 10, ///< Addresses Read From Flash must be even.
            'SW_ERROR_FLASH_WRITE_INVALID_ADDRESS' , # = 11, ///<An attempt to write or erase flash was made to a protected or non-existant area
	    'SW_ERROR_INVALID_PIN_COMMAND' , # = 12, ///< The pin command 0xC1, 0xC2, etc is not suported by this pin mode (May vary by model)
            'SW_ERROR_PIN_CONFIG_WRONG_ORDER' , # = 13, ///<The called pin command 0xC1, 0xC2 was called before other required prior commands (e.g. 0xC0)
            'SW_ERROR_WS2812_INDEX_GT_LEDS' , # = 14, ///<The command references an index that is greater or equal to the number of leds
            'SW_ERROR_PIN_NOT_CAPABLE' , # = 15, ///<The commanded pin does not have the hardware support to perform the commanded pin mode
	    'SW_ERROR_HW_RESOURCE_IN_USE' , # = 16, ///<The requested hardware or software resource in use has already been exclusively claimed by another pin
            'SW_ERROR_INVALID_PARAMETER_3' , # = 17, ///<The pin configuration parameter in Byte 3 was invalid
            'SW_ERROR_INVALID_PARAMETER_4' , # = 18, ///<The pin configuration parameter in Byte 4 was invalid
            'SW_ERROR_INVALID_PARAMETER_5' , # = 19, ///<The pin configuration parameter in Byte 5 was invalid
            'SW_ERROR_INVALID_PARAMETER_6' , # = 20, ///<The pin configuration parameter in Byte 6 was invalid
            'SW_ERROR_INVALID_PARAMETER_7' , # = 21, ///<The pin configuration parameter in Byte 7 was invalid
            'SW_ERROR_PIN_NUMBER_TOO_HIGH' , # = 22, ///<The pin number indicated was greater than the greatest avaialable pin
            'SW_ERROR_PIN_IS_COMM_INTERFACE' , # = 23, ///<The pin number indicated is currently being used for Serial Wombat protocol communicaitons
            'SW_ERROR_ANALOG_CAL_WRONG_UNLOCK' , # = 24, ///<The unlock value provided to write analog calibration was incorrect.
            'SW_ERROR_2ND_INF_WRONG_UNLOCK' , # = 25, ///<The unlock value provided to enable the 2nd interface was incorrect.
            'SW_ERROR_2ND_INF_UNAVAILABLE' , # = 26, ///<The 2nd interface hardware was not avaialble to claim
            'SW_ERROR_UART_NOT_INITIALIZED' , # = 27, ///<A UART operation was requested but the UART was not intialized
            'SW_ERROR_CMD_BYTE_1' , # = 28, ///< Byte 1 of the command was invalid
            'SW_ERROR_CMD_BYTE_2' , # = 29, ///< Byte 2 of the command was invalid
            'SW_ERROR_CMD_BYTE_3' , # = 30, ///< Byte 3 of the command was invalid
            'SW_ERROR_CMD_BYTE_4' , # = 31, ///< Byte 4 of the command was invalid
            'SW_ERROR_CMD_BYTE_5' , # = 32, ///< Byte 5 of the command was invalid
            'SW_ERROR_CMD_BYTE_6' , # = 33, ///< Byte 6 of the command was invalid
            'SW_ERROR_CMD_BYTE_7' , # = 34, ///< Byte 7 of the command was invalid
            'SW_ERROR_CMD_UNSUPPORTED_BAUD_RATE' , # = 35, ///< invalid baud rate enumeration    
            'SW_ERROR_QUEUE_RESULT_INSUFFICIENT_USER_SPACE' , # = 36,
	'SW_ERROR_QUEUE_RESULT_UNALIGNED_ADDRESS' , # = 37,
	'SW_ERROR_QUEUE_RESULT_INVALID_QUEUE' , # = 38,
	'SW_ERROR_QUEUE_RESULT_FULL' , # = 39,
	'SW_ERROR_QUEUE_RESULT_EMPTY' , # = 40,
	'SW_ERROR_DATA_NOT_AVAILABLE' , # = 41,
            'SW_ERROR_TM1637_WRONG_MODE' , # = 42, ///< The TM1637 pin is configured for the wrong TM1637 mode to process the command
           'SW_ERROR_RUB_INVALID_ADDRESS' , # = 43, ///<An attempt to read user buffer address outside the user buffer was attempted.
            'SW_ERROR_UNKNOWN_OUTPUTSCALE_COMMAND' , # = 44, // The command index for an output scaling command is not supported on this firmware
            'SW_ERROR_UNKNOWN_INPUT_PROCESS_COMMAND' , # = 45, // The command index for an inputProcess command is not supported on this firmware
	    'SW_ERROR_PULSE_ON_CHANGE_ENTRY_OUT_OF_RANGE' , # = 46, // The pulse on change entry number exceeded the number of entries
	    'SW_ERROR_PULSE_ON_CHANGE_UNKNOWN_MODE' , # = 47, // The pulse on change Mode requested is unknown
        'SW_ERROR_UNKNOWN_QUEUE_TYPE' ,# = 48, ///< This Queue type is not supported on this firwmare
            'SW_ERROR_CAPTURE_PACKET_WRONG',# = 49, ///< The capture packet did not have the correct protection bytes
	    'SW_ERROR_PS2KB_WRONG_MODE',# = 50, ///< The command issued is not available for the current Queue mode
]


    def error(self):
        outstr = "ERROR: "
        errornum = ((self.dataList[1] - 0x30) * 10000 +
                   (self.dataList[2] - 0x30) * 1000 +
                   (self.dataList[3] - 0x30) * 100 +
                   (self.dataList[4] - 0x30) * 10 +
                   (self.dataList[5] - 0x30)) 
        if (errornum <= 47 and errornum >= 0 ):
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
        return "sleep Command"

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
        return f'Ascii Set public data pin: {pin}: {chr(self.datalist[3])}{chr(self.datalist[4])}{chr(self.datalist[5])}{chr(self.datalist[6])}{chr(self.datalist[7])}'

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
        else:
            return f'Configure Pin {self.dataList[1]} mode {self.dataList[2]} '

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
            else:
                return f'Set pin {self.dataList[1]} IP read avg, filtered' 
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} Input Process unknown command'


    def configureOutputScaling(self): #TODO These aren't right
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
        elif (self.dataList[3] == 50):
            return f'Configure Pin {self.dataList[1]} OS hysteresis high Limit{self.dataList[4] + 256 * self.dataList[5]} High Output: {self.dataList[6] + 256 * self.dataList[7]}'  
        elif (self.dataList[3] == 51):
            return f'Configure Pin {self.dataList[1]} OS hysteresis Low Limit{self.dataList[4] + 256 * self.dataList[5]} Low Output: {self.dataList[6] + 256 * self.dataList[7]}'  
        elif (self.dataList[3] == 52):
            return f'Configure Pin {self.dataList[1]} OS hysteresis Last value {self.dataList[4] + 256 * self.dataList[5]}'  
        elif (self.dataList[3] == 100):
            return f'Configure Pin {self.dataList[1]} OS PID  KP: {self.dataList[4] + 256 * self.dataList[5]} KI:{self.dataList[6] + 256 * self.dataList[7]}'  
        elif (self.dataList[3] == 101):
            return f'Configure Pin {self.dataList[1]} OS PID  KD: {self.dataList[4] + 256 * self.dataList[5]} '  
        elif (self.dataList[3] == 102):
            return f'Configure Pin {self.dataList[1]} OS PID  Integrator to zero'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} Input Process unknown command'

    def setDigitalIO(self):
        if self.dataList[0] == 0xC8:
            if (self.dataList[3] == 0):
                state = 'Low'
                if (self.dataList[6] == 1):
                    state = state + ', Open Drain'
            elif (self.dataList[3] == 1):
                state = 'High'
                if (self.dataList[6] == 1):
                    state = state + ', Open Drain'

            elif (self.dataList[3] == 2):
                state = 'Input'
            else: 
                state = 'Unknown'

            if (self.dataList[4] == 0):
                state = state + ' - Pull Up Disabled'
            else:
                state = state + ' - Pull Up Enabled'


            return f'Set pin {self.dataList[1]} Digital {state}'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} Digital IO- Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setControlled(self):
            return f'Set pin {self.dataList[1]} Controlled - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setServo(self):
        if self.dataList[0] == 0xC8:
            reverse = self.dataList[6] > 0
            position = self.dataList[4] + self.dataList[5] * 256
            return f'Set pin {self.dataList[1]} Servo- Position: {position} reverse:{reverse} '
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} Servo- fixedTime: {self.dataList[3] + self.dataList[4] * 256} uS, variableTime:{self.dataList[5] + self.dataList[6] * 256} uS'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} Servo- Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setThroughputConsumer(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} Throughput Consumer Reset all to Zero'
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} Throughput Consumer entry {self.dataList[3]} to {self.dataList[4] + self.dataList[5] * 256}'
        elif self.dataList[0] == 0xCA:
            return f'Set pin {self.dataList[1]} Throughput Consumer consume {self.dataList[3] + self.dataList[3] * 256} now'
        else:
            return f'Set pin {self.dataList[1]} Throughput Coonsumer ' 

    def setQuadEnc(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} QuadEnc- debounce count:{self.dataList[3] + self.dataList[4] * 256} 2nd Pin:{self.dataList[5]}  Read State: {self.dataList[6]} Pull Ups Enabled: {self.dataList[7]} '
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} Quad Enc- Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

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
            return f'Set pin {self.dataList[1]} Analog Input - Set Total Samples {self.dataList[3]}, filter constant {self.dataList[5] + self.dataList[6] * 256} '
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
            return f'Set pin {self.dataList[1]} Resistance Input - Set Total Samples {self.dataList[3]}, filter constant {self.dataList[5] + self.dataList[6] * 256} '
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


    def setProtectedOutput(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} Protected Output - Expected Value {self.dataList[3] + 256 * self.dataList[4]} Debounce time: {self.dataList[5]} monitorPin: {self.dataList[6]} Safe State: {self.dataList[7]}'
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} Protected Output - Match Method: {self.dataList[3]}'
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
            return f'Set pin {self.dataList[1]} TM1637: CLK Pin:{self.dataList[3]}, Digits: {self.dataList[4]}  Mode: {self.dataList[5]} Source: {self.dataList[6]} Bright: {self.dataList[7]}'
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} TM1637: Map 0 dig:{self.dataList[3]}, Map 1 dig: {self.dataList[4]}  Map 2 dig: {self.dataList[5]} Map 3 dig: {self.dataList[6]} Map 4 dig: {self.dataList[7]}'
        elif self.dataList[0] == 0xCA:
            return f'Set pin {self.dataList[1]} TM1637: Map 5 dig:{self.dataList[3]}'
        elif self.dataList[0] == 0xCB:
            return f'Set pin {self.dataList[1]} TM1637: Brightness:{self.dataList[3]}'
        elif self.dataList[0] == 0xCC:
            return f'Set pin {self.dataList[1]} TM1637: Output 0:{self.dataList[3]},  Output 1: {self.dataList[4]}  Output 2: {self.dataList[5]} Output 3: {self.dataList[6]} Output 4: {self.dataList[7]}  Anim: Addr: {self.hex4(3)} Delay:{self.hex4(5)} Frames: {self.dataList[7]}'
        elif self.dataList[0] == 0xCD:
            return f'Set pin {self.dataList[1]} TM1637: Decimal bitmap:{self.dataList[3]}'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} TM1637 - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setWS2812(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} WS2812: Buff indx: {self.hex4(3)}, #LEDs:{self.dataList[5]}'
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} WS2812: Set LED:{self.dataList[3]} Blue: {self.hex2(4)} Green: {self.hex2(5)} Red: {self.hex2(5)}'
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
            else:
                self.unknown();
                return f'Set pin {self.dataList[1]} WS2812: Mode UNKNOWN' 
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} WS2812 - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '



    def setPWM(self):
        if self.dataList[0] == 0xC8:
            counts = self.dataList[4] + self.dataList[5] * 256;
            
            return f'Set pin {self.dataList[1]} PWM- Duty Cycle: {counts}/65535, {counts * 100 / 65535}%  Invert: {self.dataList[6]}'
        else:
            self.unknown();
            return f'Set pin {self.dataList[1]} PWM - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '


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
