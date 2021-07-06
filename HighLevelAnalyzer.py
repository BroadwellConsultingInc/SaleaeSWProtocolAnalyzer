# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    my_string_setting = StringSetting()
    my_number_setting = NumberSetting(min_value=0, max_value=100)
    my_choices_setting = ChoicesSetting(choices=('A', 'B'))

    
    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'SW Packet': {
            'format': '[{{data.address}}]  {{data.data}}'
        }
    }
    wombat_frame = None
    dataList = [0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55]
    dataCount = 0
    address_byte = 0

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''

        print("Settings:", self.my_string_setting,
              self.my_number_setting, self.my_choices_setting)


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
            self.wombat_frame = AnalyzerFrame("SW Packet", frame.start_time, frame.end_time, {
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
            self.wombat_frame.data["read"] = frame.data["read"];

        elif frame.type == "data":
            if (self.dataCount < 8):
                data_byte = frame.data["data"][0]
                self.dataList[self.dataCount] = data_byte
                self.dataCount += 1

        elif frame.type == "stop":
            self.wombat_frame.end_time = frame.end_time
            self.generateString();
            new_frame = self.wombat_frame
            self.wombat_frame = None
            if (self.address_byte >= 0x6C and self.address_byte <= 0x6F):
                self.address_byte = 0
                return new_frame
            else:
                self.address_byte = 0


    def generateString(self):
        outstr = ""
        if self.wombat_frame.data["read"]:
            outstr = "RESP: "
        else:
            outstr = "CMD: "

        if self.dataList[0] == 0x21:
            outstr = outstr + self.echo()
        if self.dataList[0] == 0x52:
            outstr = outstr + self.reset()
        elif self.dataList[0] == 0x56:
            outstr = outstr + self.version()
        elif self.dataList[0] == 0x81:
            outstr = outstr + self.readPin()
        elif self.dataList[0] == 0x82:
            outstr = outstr + self.writePin()
        elif  self.dataList[0] == 0xA0:
            outstr = outstr + self.readRam() 
        elif  self.dataList[0] == 0xA1:
            outstr = outstr + self.readFlash() 
        elif  self.dataList[0] == 0xA3:
            outstr = outstr + self.writeRam() 
        elif (self.dataList[0] >= 0xC8 and self.dataList[0] <= 0xDA):
            outstr = outstr + self.configurePin() 


        self.wombat_frame.data["data"] = outstr










    def echo(self):
        outstr = "Echo: "
        outstr =  outstr +  "".join('{:02X} '.format(x) for x in self.dataList[-7:])
        return outstr

    def reset(self):
#        if ("".join(self.dataList[0:8]) == "ReSeT!#*"):
#            outstr = "Reset Command"
#        else:
#            outstr = "Reset Wrong Command"
        return "Reset Command"


    def readRam(self):
        address = self.dataList[1] + 256 * self.dataList[2] 
        if self.wombat_frame.data["read"]:
            value =self.dataList[3]
            return f'Read RAM Address: 0x{"{:04X} ".format(address)} Value: {value}/0x{"{:02X} ".format(value)} '
        else:
            return f'Read RAM Address: 0x{"{:04X} ".format(address)}'

    def readFlash(self):
        address = self.dataList[1] + 256 * self.dataList[2] 
        if self.wombat_frame.data["read"]:
            value =self.dataList[4] + self.dataList[5] * 256
            return f'Read Flash Address: 0x{"{:04X} ".format(address)} Value: {value}/0x{"{:04X} ".format(value)} '
        else:
            return f'Read Flash Address: 0x{"{:04X} ".format(address)}'

    def writeRam(self):
        address = self.dataList[1] + 256 * self.dataList[2]  + self.dataList[3] * 65536 + self.dataList[4] * 256 * 65536
        value =self.dataList[5]
        return f'Write RAM Address: 0x{"{:04X} ".format(address)} Value: {value}/0x{"{:02X} ".format(value)} '



    def version(self):
        if self.wombat_frame.data["read"]:
            category = chr(self.dataList[1])
            model = ''.join(chr(x) for x in self.dataList[2:5])
            ver =''.join(chr(x) for x in self.dataList[5:8])
            return f'Version-- Category: {category} Model: {model} FW Ver: {ver} '
        else:
            return "Version "

    def readPin(self):
        if self.wombat_frame.data["read"]:
            if (self.dataList[1] == 0x40):
                return f'Read incrementingCounter: {self.dataList[2] + self.dataList[3] * 256 + self.dataList[4] * 65536 + self.dataList[5] * 256 * 65536}'
            elif (self.dataList[1] == 0x42):
                return f'Read 1.024 V reference:({hex( (self.dataList[2] + self.dataList[3] * 256)) }).  Inferred Vcc: {int( 1024.0 * 65536 /(self.dataList[2] + self.dataList[3] * 256))} mv '
            elif (self.dataList[1] == 0x43):
                return f'Read Frames Run: {self.dataList[2] + self.dataList[3] * 256 + self.dataList[4] * 65536 + self.dataList[5] * 256 * 65536}'
            elif (self.dataList[1] == 0x45):
                return f'Read Overflow Frames: {self.dataList[2] + self.dataList[3]}'
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
        elif self.dataList[2] == 5:
            return self.setQuadEnc();
        elif self.dataList[2] == 7:
            return self.setWatchdog();
        elif self.dataList[2] == 8:
            return self.setProtectedOutput();
        elif self.dataList[2] == 10:
            return self.setDebounce();
        elif self.dataList[2] == 16:
            return self.setPWM();
        elif self.dataList[2] == 17:
            return self.setUARTTXRX();
        elif self.dataList[2] == 18:
            return self.setPulseTimer();
        else:
            return f'Configure Pin {self.dataList[1]} mode {self.dataList[2]} '


    
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
            return f'Set pin {self.dataList[1]} Servo- Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setQuadEnc(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} QuadEnc- debounce count:{self.dataList[3] + self.dataList[4] * 256} 2nd Pin:{self.dataList[5]}  Read State: {self.dataList[6]} Pull Ups Enabled: {self.dataList[7]} '
        else:
            return f'Set pin {self.dataList[1]} Quad Enc- Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setWatchdog(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} Watchdog: NonTimeout State:{self.dataList[3]}, TimeoutState:{self.dataList[4]}, Timeout (mS): {self.dataList[5] + 256 * self.dataList[6]}, ResetOnTimeout: {self.dataList[7]}    '
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} Watchdog: Use Pin Bitfield: {self.dataList[3]}, PinBitfield:{self.dataList[4]}, Delay in TimeoutState (mS): {self.dataList[5] + 256 * self.dataList[6]}     '

        else:
            return f'Set pin {self.dataList[1]} Watchdog - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setAnalogInput(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} Analog Input - (Initialization) '
        elif self.dataList[0] == 0xC9:
            return f'Set pin {self.dataList[1]} Analog Input - Set Total Samples {self.dataList[3]}, filter constant {self.dataList[5] + self.dataList[6] * 256} '
        elif self.dataList[0] == 0xCB:
            if self.wombat_frame.data["read"]:
                return f'Set pin {self.dataList[1]} Analog Input - Min: {self.dataList[3] + self.dataList[4] * 256} Max: {self.dataList[5] + self.dataList[6] * 256}'
            else:
                return f'Set pin {self.dataList[1]} Analog Input - Read Min/Max, Reset MinMax: {self.dataList[3]} '
        elif self.dataList[0] == 0xCC:
            if self.wombat_frame.data["read"]:
                return f'Set pin {self.dataList[1]} Analog Input - Averaged: {self.dataList[3] + self.dataList[4] * 256} Filtered: {self.dataList[5] + self.dataList[6] * 256}'
            else:
                return f'Set pin {self.dataList[1]} Analog Input - Read Averaged / Filtered '
        else:
            return f'Set pin {self.dataList[1]} Analog Input - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setProtectedOutput(self):
#        if self.dataList[0] == 0xC8:
#            reverse = self.dataList[6] > 0
#            position = self.dataList[4] + self.dataList[5] * 256
#            return f'Set pin {self.dataList[1]} Servo- Position: {position} reverse:{reverse} '
#        else:
            return f'Set pin {self.dataList[1]} Protected Output - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '

    def setDebounce(self):
        if self.dataList[0] == 0xC8:
            return f'Set pin {self.dataList[1]} Debounce:  Pull ups: {self.dataList[7]}, period (mS):{self.dataList[3]},  invert: {self.dataList[5]} '
        if self.dataList[0] == 0xC9:
            if self.wombat_frame.data["read"]:
                return f'Set pin {self.dataList[1]} Debounce:  Level: {self.dataList[3]}, transitions:{self.dataList[4] + self.dataList[5] * 256}  Stable mS:  {self.dataList[6] + self.dataList[7] * 256}'
            else:
                return f'Set pin {self.dataList[1]} Debounce:  Request data'
        else:
            return f'Set pin {self.dataList[1]} Debounced Inp. - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '


    def setPWM(self):
        if self.dataList[0] == 0xC8:
            counts = self.dataList[4] + self.dataList[5] * 256;
            
            return f'Set pin {self.dataList[1]} PWM- Duty Cycle: {counts}/65535, {counts * 100 / 65535}%  Invert: {self.dataList[6]}'
        else:
            return f'Set pin {self.dataList[1]} PWM - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '


    def setUARTTXRX(self):
        if self.dataList[0] == 0xC8:
            baudList = [ 300,  1200, 2400,  4800,  9600,  19200,  38400,  57600 , 115200 ]
            if self.dataList[3] <= 8:
                baud = baudList[self.dataList[3]]
            else:
                baud = 115200
            return f'Set pin {self.dataList[1]} UART- Baud: {baud}, Rx Pin: {self.dataList[4]}, Tx Pin {self.dataList[5]}'

        elif self.dataList[0] == 0xC9:
            if self.wombat_frame.data["read"]:
                return f'Set pin {self.dataList[1]} UART- Transmit data: {self.dataList[3]} bytes tx buffer available, {self.dataList[4]} bytes available for RX'
            else:
                return f'Set pin {self.dataList[1]} UART- Transmit data: {"".join("{:02x}".format(x) for x in self.dataList[4:4 + self.dataList[3]])}'
        elif self.dataList[0] == 0xCA:
            if self.wombat_frame.data["read"]:
                return f'Set pin {self.dataList[1]} UART- Read data: Read {self.dataList[3]} bytes:{"".join("{:02x} ".format(x) for x in self.dataList[4:4 + self.dataList[3]])} '
            else:
                return f'Set pin {self.dataList[1]} UART- Read data: up to {self.dataList[3]} bytes'

        elif self.dataList[0] == 0xCB:
            if self.wombat_frame.data["read"]:
                return f'Set pin {self.dataList[1]} UART- Peek data:  {self.dataList[3]} bytes tx buffer available, {self.dataList[3]} bytes rx available, 1st available data value: {hex(self.dataList[5])}'
            else:
                return f'Set pin {self.dataList[1]} UART- Peek data'
                
            
        else:
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
            if self.wombat_frame.data["read"]:
                return f'Set pin {self.dataList[1]} Pulse Timer- High time: {self.dataList[3] + self.dataList[4] * 256}  Low time: {self.dataList[5] + self.dataList[6] * 256} Count LSB: {self.dataList[7]}'
            else:
               return f'Set pin {self.dataList[1]} Pulse Timer- Read High Time and Low Time'
        elif self.dataList[0] == 0xCA:
            if self.wombat_frame.data["read"]:
                return f'Set pin {self.dataList[1]} Pulse Timer- High time: {self.dataList[3] + self.dataList[4] * 256}  Count: {self.dataList[5] + self.dataList[6] * 256} Overflow: {self.dataList[7]}'
            else:
                return f'Set pin {self.dataList[1]} Pulse Timer- Read High Time and Low Time'
        else:
            return f'Set pin {self.dataList[1]} Pulse Timer - Unknown command {"".join("{:02X} ".format(self.dataList[0]))} '




