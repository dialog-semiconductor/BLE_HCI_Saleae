# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions
# Author :Niek Ilmer

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

OPCODE_dict = {
	'LE_SET_EVENT_MASK'																			:0x2001,
	'LE_READ_BUFFER_SIZE'																			:0x2002,
	'LE_READ_LOCAL_SUPPORTED_FEATURES'																			:0x2003,
	'LE_SET_RANDOM_ADDRESS'																			:0x2005,
	'LE_SET_ADVERTISING_PARAMETERS'																			:0x2006,
	'LE_READ_ADVERTISING_CHANNEL_TX_POWER'																			:0x2007,
	'LE_SET_ADVERTISING_DATA'																			:0x2008,
	'LE_SET_SCAN_RESPONSE_DATA'																			:0x2009,
	'LE_SET_ADVERTISE_ENABLE'																			:0x200A,
	'LE_SET_SCAN_PARAMETERS'																			:0x200B,
	'LE_SET_SCAN_ENABLE'																			:0x200C,
	'LE_CREATE_CONNECTION'																			:0x200D,
	'LE_CREATE_CONNECTION_CANCEL'																			:0x200E,
	'LE_READ_WHITE_LIST_SIZE'																			:0x200F,
	'LE_CLEAR_WHITE_LIST'																			:0x2010,
	'LE_ADD_DEVICE_TO_WHITE_LIST'																			:0x2011,
	'LE_REMOVE_DEVICE_FROM_WHITE_LIST'																			:0x2012,
	'LE_CONNECTION_UPDATE'																			:0x2013,
	'LE_SET_HOST_CHANNEL_CLASSIFICATION'																			:0x2014,
	'LE_READ_CHANNEL_MAP'																			:0x2015,
	'LE_READ_REMOTE_USED_FEATURES'																			:0x2016,
	'LE_ENCRYPT'																			:0x2017,
	'LE_RAND'																			:0x2018,
	'LE_START_ENCRYPTION'																			:0x2019,
	'LE_LONG_TERM_KEY_REQUESTED_REPLY'																			:0x201A,
	'LE_LONG_TERM_KEY_REQUESTED_NEGATIVE_REPLY'																			:0x201B,
	'LE_READ_SUPPORTED_STATES'																			:0x201C,
	'LE_RECEIVER_TEST'																			:0x201D,
	'LE_TRANSMITTER_TEST'																			:0x201E,
	'LE_TEST_END_COMMAND'																			:0x201F,
	'LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY'																			:0x2020,
	'LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY'																			:0x2021,
	'LE_SET_DATA_LENGTH'																			:0x2022,
	'LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH'																			:0x2023,
	'LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH'																			:0x2024,
	'LE_READ_LOCAL_P256_PUBLIC_KEY'																			:0x2025,
	'LE_GENERATE_DHKEY'																			:0x2026,
	'LE_ADD_DEVICE_TO_RESOLVING_LIST'																			:0x2027,
	'LE_REMOVE_DEVICE_FROM_RESOLVING_LIST'																			:0x2028,
	'LE_CLEAR_RESOLVING_LIST'																			:0x2029,
	'LE_READ_RESOLVING_LIST_SIZE'																			:0x202A,
	'LE_READ_PEER_RESOLVABLE_ADDRESS'																			:0x202B,
	'LE_READ_LOCAL_RESOLVABLE_ADDRESS'																			:0x202C,
	'LE_SET_ADDRESS_RESOLUTION_ENABLE'																			:0x202D,
	'LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT'																			:0x202E,
	'LE_READ_MAXIMUM_DATA_LENGTH'																			:0x202F,
	'LE_SET_DEFAULT_PHY'																			:0x2031,
	'LE_SET_PHY'																			:0x2032,

	'DISCONNECT'																			:0x0406,
	'READ_REMOTE_VERSION_INFORMATION'																			:0x041D,
	'SET_EVENT_MASK'																			:0x0C01,
	'HCI_RESET'																			:0x0C03,
	'READ_TRANSMIT_POWER_LEVEL'																			:0x0C2D,
	'SET_CONTROLLER_TO_HOST_FLOW_CONTROL'																			:0x0C31,
	'HOST_BUFFER_SIZE'																			:0x0C33,
	'HOST_NUMBER_OF_COMPLETED_PACKETS'																			:0x0C35,
	'SET_EVENT_MASK_PAGE_2'																			:0x0C63,
	'READ_AUTHENTICATED_PAYLOAD_TIMEOUT'																			:0x0C7B,
	'WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT'																			:0x0C7C,
	'READ_LOCAL_VERSION_INFORMATION'																			:0x1001,
	'READ_LOCAL_SUPPORTED_COMMANDS'																			:0x1002,
	'READ_LOCAL_SUPPORTED_FEATURES'																			:0x1003,
	'READ_BD_ADDR'																			:0x1009,
	'READ_RSSI'																			:0x1405,

	'HCI_EXTENSION_SET_RX_GAIN'																			:0xFC00,
	'HCI_EXTENSION_SET_TX_POWER'																			:0xFC01,
	'HCI_EXTENSION_ONE_PACKET_PER_EVENT'																			:0xFC02,
	'HCI_EXTENSION_CLOCK_DIVIDE_ON_HALT'																			:0xFC03,
	'HCI_EXTENSION_DECLARE_NV_USAGE'																			:0xFC04,
	'HCI_EXTENSION_DECRYPT'																			:0xFC05,
	'HCI_EXTENSION_SET_LOCAL_SUPPORTED_FEATURES'																			:0xFC06,
	'HCI_EXTENSION_SET_FAST_TX_RESPONSE_TIME'																			:0xFC07,
	'HCI_EXTENSION_MODEM_TEST_TX'																			:0xFC08,
	'HCI_EXTENSION_MODEM_HOP_TEST_TX'																			:0xFC09,
	'HCI_EXTENSION_MODEM_TEST_RX'																			:0xFC0A,
	'HCI_EXTENSION_END_MODEM_TEST'																			:0xFC0B,
	'HCI_EXTENSION_SET_BDADDR'																			:0xFC0C,
	'HCI_EXTENSION_SET_SCA'																			:0xFC0D,
	'HCI_EXTENSION_ENABLE_PTM1'																			:0xFC0E,
	'HCI_EXTENSION_SET_FREQUENCY_TUNING'																			:0xFC0F,
	'HCI_EXTENSION_SAVE_FREQUENCY_TUNING'																			:0xFC10,
	'HCI_EXTENSION_SET_MAX_DTM_TX_POWER'																			:0xFC11,
	'HCI_EXTENSION_MAP_PM_IO_PORT'																			:0xFC12,
	'HCI_EXTENSION_DISCONNECT_IMMEDIATE'																			:0xFC13,
	'HCI_EXTENSION_PACKET_ERROR_RATE'																			:0xFC14,
	'HCI_EXTENSION_PACKET_ERROR_RATE_BY_CHANNEL1'																			:0xFC15,
	'HCI_EXTENSION_EXTEND_RF_RANGE'																			:0xFC16,
	'HCI_EXTENSION_ADVERTISER_EVENT_NOTICE'																			:0xFC17,
	'HCI_EXTENSION_CONNECTION_EVENT_NOTICE'																			:0xFC18,
	'HCI_EXTENSION_HALT_DURING_RF'																			:0xFC19,
	'HCI_EXTENSION_SET_SLAVE_LATENCY_OVERRIDE'																			:0xFC1A,
	'HCI_EXTENSION_BUILD_REVISION'																			:0xFC1B,
	'HCI_EXTENSION_DELAY_SLEEP'																			:0xFC1C,
	'HCI_EXTENSION_RESET_SYSTEM'																			:0xFC1D,
	'HCI_EXTENSION_OVERLAPPED_PROCESSING'																			:0xFC1E,
	'HCI_EXTENSION_NUMBER_COMPLETED_PACKETS_LIMIT'																			:0xFC1F,
	'HCI_EXTENSION_GET_CONNECTION_INFORMATION'																			:0xFC20,
	'HCI_EXTENSION_SET_MAX_DATA_LENGTH'																			:0xFC21,
	'HCI_EXTENSION_SCAN_EVENT_NOTICE'																			:0xFC22,
	'HCI_EXTENSION_SCAN_REQUEST_REPORT'																			:0xFC23,

	'L2CAP_DISCONNECTION_REQUEST'																			:0xFC86,
	'L2CAP_CONNECTION_PARAMETER_UPDATE_REQUEST'																			:0xFC92,
	'L2CAP_CONNECTION_REQUEST'																			:0xFC94,
	'L2CAP_CONNECTION_RESPONSE'																			:0xFC95,
	'L2CAP_FLOW_CONTROL_CREDIT'																			:0xFC96,
	'L2CAP_DATA'																			:0xFCF0,
	'L2CAP_REGISTER_PSM'																			:0xFCF1,
	'L2CAP_DEREGISTER_PSM'																			:0xFCF2,
	'L2CAP_PSM_INFO'																			:0xFCF3,
	'L2CAP_PSM_CHANNELS'																			:0xFCF4,
	'L2CAP_CHANNEL_INFO'																			:0xFCF5,

	'ATT_ERROR_RESPONSE'																			:0xFD01,
	'ATT_EXCHANGE_MTU_REQUEST'																			:0xFD02,
	'ATT_EXCHANGE_MTU_RESPONSE'																			:0xFD03,
	'ATT_FIND_INFORMATION_REQUEST'																			:0xFD04,
	'ATT_FIND_INFORMATION_RESPONSE'																			:0xFD05,
	'ATT_FIND_BY_TYPE_VALUE_REQUEST'																			:0xFD06,
	'ATT_FIND_BY_TYPE_VALUE_RESPONSE'																			:0xFD07,
	'ATT_READ_BY_TYPE_REQUEST'																			:0xFD08,
	'ATT_READ_BY_TYPE_RESPONSE'																			:0xFD09,
	'ATT_READ_REQUEST'																			:0xFD0A,
	'ATT_READ_RESPONSE'																			:0xFD0B,
	'ATT_READ_BLOB_REQUEST'																			:0xFD0C,
	'ATT_READ_BLOB_RESPONSE'																			:0xFD0D,
	'ATT_READ_MULTIPLE_REQUEST'																			:0xFD0E,
	'ATT_READ_MULTIPLE_RESPONSE'																			:0xFD0F,
	'ATT_READ_BY_GROUP_TYPE_REQUEST'																			:0xFD10,
	'ATT_READ_BY_GROUP_TYPE_RESPONSE'																			:0xFD11,
	'ATT_WRITE_REQUEST'																			:0xFD12,
	'ATT_WRITE_RESPONSE'																			:0xFD13,
	'ATT_PREPARE_WRITE_REQUEST'																			:0xFD16,
	'ATT_PREPARE_WRITE_RESPONSE'																			:0xFD17,
	'ATT_EXECUTE_WRITE_REQUEST'																			:0xFD18,
	'ATT_EXECUTE_WRITE_RESPONSE'																			:0xFD19,
	'ATT_HANDLE_VALUE_NOTIFICATION'																			:0xFD1B,
	'ATT_HANDLE_VALUE_INDICATION'																			:0xFD1D,
	'ATT_HANDLE_VALUE_CONFIRMATION'																			:0xFD1E,

	'GATT_DISC_ALL_CHAR_DESCS'																			:0xFD84,
	'GATT_DISCOVER_CHARACTERISTICS_BY_UUID'																			:0xFD88,
	'GATT_READ'																			:0xFD8A,
	'GATT_WRITE'																			:0xFD92,
	'GATT_WRITE_LONG'																			:0xFD96,

	'GAP_DEVICE_INITIALIZATION'																			:0xFE00,
	'GAP_CONFIGURE_DEVICE_ADDRESS'																			:0xFE03,
	'GAP_DEVICE_DISCOVERY_REQUEST'																			:0xFE04,
	'GAP_DEVICE_DISCOVERY_CANCEL'																			:0xFE05,
	'GAP_MAKE_DISCOVERABLE'																			:0xFE06,
	'GAP_UPDATE_ADVERTISING_DATA'																			:0xFE07,
	'GAP_END_DISCOVERABLE'																			:0xFE08,
	'GAP_ESTABLISH_LINK_REQUEST'																			:0xFE09,
	'GAP_TERMINATE_LINK_REQUEST'																			:0xFE0A,
	'GAP_AUTHENTICATE'																			:0xFE0B,
	'GAP_PASSKEY_UPDATE'																			:0xFE0C,
	'GAP_SLAVE_SECURITY_REQUEST'																			:0xFE0D,
	'GAP_SIGNABLE'																			:0xFE0E,
	'GAP_BOND'																			:0xFE0F,
	'GAP_TERMINATE_AUTH'																			:0xFE10,
	'GAP_UPDATE_LINK_PARAMETER_REQUEST'																			:0xFE11,
	'GAP_UPDATE_LINK_PARAMETER_REQUEST_REPLY'																			:0xFE12,
	'GAP_SET_PARAMETER'																			:0xFE30,
	'GAP_GET_PARAMETER'																			:0xFE31,
	'GAP_RESOLVE_PRIVATE_ADDRESS'																			:0xFE32,
	'GAP_SET_ADVERTISEMENT_TOKEN'																			:0xFE33,
	'GAP_REMOVE_ADVERTISEMENT_TOKEN'																			:0xFE34,
	'GAP_UPDATE_ADVERTISEMENT_TOKENS'																			:0xFE35,
	'GAP_BOND_SET_PARAMETER'																			:0xFE36,
	'GAP_BOND_GET_PARAMETER'																			:0xFE37,
	
	'UTIL_RESERVED'																			:0xFE80,
	'UTIL_NV_READ'																			:0xFE81,
	'UTIL_NV_WRITE'																			:0xFE82,
	'UTIL_FORCE_BOOT'																			:0xFE83,
	'UTIL_BUILD_REVISION'																			:0xFE84,

	'RESERVED'																			:0xFF00,

	'USER_PROFILES'																			:0xFF80,

	'HCI_CMD_OPCODE_CONT_PKT_TX'																			:0x201E,
	'HCI_CMD_OPCODE_START_PKT_RX'																			:0x201D,
	'HCI_CMD_OPCODE_STOPTEST'																			:0x201F,
	'HCI_CMD_OPCODE_RESET'																			:0x0C03,
	'HCI_CUSTOM_ACTION_CMD_OPCODE'																			:0xFE00,
	'HCI_SLEEP_TEST_CMD_OPCODE'																			:0xFE01,
	'HCI_XTAL_TRIM_CMD_OPCODE'																			:0xFE02,
	'HCI_OTP_RW_CMD_OPCODE'																			:0xFE03,
	'HCI_OTP_READ_CMD_OPCODE'																			:0xFE04,
	'HCI_OTP_WRITE_CMD_OPCODE'																			:0xFE05,
	'HCI_REGISTER_RW_CMD_OPCODE'																			:0xFE06,
	'HCI_AUDIO_TEST_CMD_OPCODE'																			:0xFE07,
	'HCI_FIRMWARE_VERSION_GET_CMD_OPCODE'																			:0xFE08,
	'HCI_CHANGE_UART_PINS_ACTION_CMD_OPCODE'																			:0xFE09,
	'HCI_RDTESTER_CMD_OPCODE'																			:0xFE0A,
	'HCI_TX_TEST_CMD_OPCODE'																			:0xFE0B,
	'HCI_START_PROD_RX_TEST_CMD_OPCODE'																			:0xFE0C,
	'HCI_END_PROD_RX_TEST_CMD_OPCODE'																			:0xFE0D,
	'HCI_UNMODULATED_ON_CMD_OPCODE'																			:0xFE0E,
	'HCI_TX_START_CONTINUE_TEST_CMD_OPCODE'																			:0xFE0F,
	'HCI_TX_END_CONTINUE_TEST_CMD_OPCODE'																			:0xFE10,
	'HCI_SENSOR_TEST_CMD_OPCODE'																			:0xFE11,
	'HCI_GPIO_SET_CMD_OPCODE'																			:0xFE12,
	'HCI_GPIO_READ_CMD_OPCODE'																			:0xFE13,
	'HCI_UART_LOOP_CMD_OPCODE'																			:0xFE14,
	'HCI_UART_BAUD_CMD_OPCODE'																			:0xFE15,
	'HCI_EXT32KHz_TEST_CMD_OPCODE'																			:0xFE16,
	'HCI_GPIO_WD_CMD_OPCODE'																			:0xFE17,
	'HCI_SLEEP_CLK_SEL_CMD_OPCODE'																			:0xFE18,
	'HCI_RANGE_EXT_EN_CMD_OPCODE'																			:0xFE19,
	'HCI_ADC_VBAT_CMD_OPCODE'																			:0xFE1A,
	'HCI_SET_TX_POWER_CMD_OPCODE'																			:0xFE1B,
	'HCI_CONFIGURE_TEST_MODE_CMD_OPCODE'																			:0xFE1C
}

EVENT_dict = {
	'LE_EVENTS'									:0x3e,
	'VENDOR_SPECIFIC_EVENT'						:0xFF,
	'DISCONNECTION_COMPLETE'					:0x05,
	'ENCRYPTION_CHANGE'							:0x08,
	'READ_REMOTE_VERSION_INFORMATION_COMPLETE'	:0x0C,
	'HCI_COMMAND_COMPLETE'						:0x0E,
	'COMMAND_STATUS'							:0x0F,
	'HARDWARE_ERROR'							:0x10,
	'NUMBER_OF_COMPLETED_PACKETS'				:0x13,
	'DATA_BUFFER_OVERFLOW'						:0x1A,
	'ENCRYPTION_KEY_REFRESH_COMPLETE'			:0x30,
	'AUTHENTICATED_PAYLOAD_TIMEOUT_EXPIRED'		:0x57
}

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
	# List of settings that a user can set for this High Level Analyzer.
	#my_string_setting = StringSetting()
	#my_number_setting = NumberSetting(min_value=0, max_value=100)
	#my_choices_setting = ChoicesSetting(choices=('A', 'B'))

	# An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
	result_types = {
		'command': {
			'format': 'OPCODE: {{data.OPCODE}}({{data.OPCODE_decoded}}), Parameter length: {{data.PAR_LEN}}, Data: {{data.data}}'
		},
		'error': {
			'format': 'Error: {{data.error}}}'
		},
		'event': {
			'format': 'EVENT: {{data.EVENT}}({{data.EVENT_decoded}}), Parameter length: {{data.PAR_LEN}}, Data: {{data.data}}'
		},
		'command complete event': {
			'format': 'Command complete event for: {{data.OPCODE}}({{data.OPCODE_decoded}}), Parameter length: {{data.PAR_LEN}}, Data: {{data.data}}'
		},
		'HCI ACL Data': {
			'format': 'Asynchronous Data, Parameter length: {{data.PAR_LEN}}, Data: {{data.data}}'
		},
		'Synchronous Data': {
			'format': 'Synchronous Data, Parameter length: {{data.PAR_LEN}}, Data: {{data.data}}'
		}
	}

	def __init__(self):
		'''
		Initialize HLA.
		
		Settings can be accessed using the same name used above.
		'''
		self.receive_buffer_pointer = 0;
		self.receiveBuffer = [];
   
		print("Dialog Semiconductor HCI interface decoder by Niek Ilmer")

	def decode(self, frame: AnalyzerFrame):
		'''
		Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

		The type and data values in `frame` will depend on the input analyzer.
		'''
		uartbuffer = int(frame.data['data'][0])
		if (( self.receive_buffer_pointer == 0 and (uartbuffer == 1 or uartbuffer == 2 or uartbuffer == 3 or uartbuffer == 4 or uartbuffer == 5)) or self.receive_buffer_pointer > 0 and (not 'error' in frame.data)):
			if self.receive_buffer_pointer == 0:
				self.startTime = frame.start_time #capture the start
				self.receiveBuffer = [uartbuffer]; 
			else:
				self.receiveBuffer.append(uartbuffer);
			if self.receiveBuffer[0] == 1:
				if(self.receive_buffer_pointer >= 3):#Byte 2 and 3 tell how big the message is
					PAR_LEN = self.receiveBuffer[3]; #Extract the parameter length from the message
					OPCODE = self.receiveBuffer[2] << 8 | self.receiveBuffer[1]; #Extract the OPCODE from the message
					if ( self.receive_buffer_pointer >= PAR_LEN + 3): #Check to see if the entire message has been received
						OPCODE_decoded = "Unknown"
						try:
							OPCODE_decoded = list(OPCODE_dict.keys())[list(OPCODE_dict.values()).index(OPCODE)]
						except ValueError: #Unknown ID
							pass
						tempMSG = AnalyzerFrame('command', self.startTime, frame.end_time, {'OPCODE_decoded':OPCODE_decoded, 'OPCODE': hex(OPCODE),'PAR_LEN': PAR_LEN, 'data':bytes(self.receiveBuffer[4:]), 'message': bytes(self.receiveBuffer)})
						self.receive_buffer_pointer = -1
			
			elif(self.receiveBuffer[0] == 4): #HCI event
				if(self.receive_buffer_pointer >= 2):#Byte 1 and 2 tell how big the message is
					PAR_LEN = self.receiveBuffer[2]; #Extract the parameter length from the message
					EVENT = self.receiveBuffer[1]; #Extract the event code from the message
					if ( self.receive_buffer_pointer >= PAR_LEN + 2): #Check to see if the entire message has been received
						EVENT_decoded = "Unknown"
						try:
							EVENT_decoded = list(EVENT_dict.keys())[list(EVENT_dict.values()).index(EVENT)]
						except ValueError: #Unknown ID
							pass
						if EVENT == EVENT_dict['HCI_COMMAND_COMPLETE']:
							OPCODE = self.receiveBuffer[5] << 8 | self.receiveBuffer[4]; #Extract the OPCODE from the message
							OPCODE_decoded = "Unknown"
							try:
								OPCODE_decoded = list(OPCODE_dict.keys())[list(OPCODE_dict.values()).index(OPCODE)]
							except ValueError: #Unknown ID
								pass
							tempMSG = AnalyzerFrame('command complete event', self.startTime, frame.end_time, {'OPCODE_decoded':OPCODE_decoded, 'EVENT_decoded':EVENT_decoded, 'OPCODE':OPCODE, 'EVENT': hex(EVENT),'PAR_LEN': PAR_LEN, 'data':bytes(self.receiveBuffer[3:]), 'message': bytes(self.receiveBuffer)})
						else:
							tempMSG = AnalyzerFrame('event', self.startTime, frame.end_time, {'EVENT_decoded':EVENT_decoded, 'EVENT': hex(EVENT),'PAR_LEN': PAR_LEN, 'data':bytes(self.receiveBuffer[3:]), 'message': bytes(self.receiveBuffer)})						
						self.receive_buffer_pointer = -1
			
			elif(self.receiveBuffer[0] == 2): #HCI ACL Data
				if(self.receive_buffer_pointer >= 2):#Byte 1 and 2 tell how big the message is
					PAR_LEN = self.receiveBuffer[4] << 8 | self.receiveBuffer[3]; #Extract the parameter length from the message
					if ( self.receive_buffer_pointer >= PAR_LEN + 3): #Check to see if the entire message has been received
						tempMSG = AnalyzerFrame('HCI ACL Data', self.startTime, frame.end_time, {'PAR_LEN': PAR_LEN, 'data':bytes(self.receiveBuffer[5:]), 'message': bytes(self.receiveBuffer)})
						self.receive_buffer_pointer = -1
			
			elif(self.receiveBuffer[0] == 3): #Synchronous Data
				if(self.receive_buffer_pointer >= 2):#Byte 1 and 2 tell how big the message is
					PAR_LEN = self.receiveBuffer[3]; #Extract the parameter length from the message
					if ( self.receive_buffer_pointer >= PAR_LEN + 3): #Check to see if the entire message has been received
						tempMSG = AnalyzerFrame('Synchronous Data', self.startTime, frame.end_time, {'PAR_LEN': PAR_LEN, 'data':bytes(self.receiveBuffer[4:]), 'message': bytes(self.receiveBuffer)})
						self.receive_buffer_pointer = -1
			
			elif(self.receiveBuffer[0] == 5): #Isochronous Data
				if(self.receive_buffer_pointer >= 2):#Byte 1 and 2 tell how big the message is
					PAR_LEN = (self.receiveBuffer[4] << 8 | self.receiveBuffer[3]) >> 2; #Extract the parameter length from the message
					if ( self.receive_buffer_pointer >= PAR_LEN + 5): #Check to see if the entire message has been received
						tempMSG = AnalyzerFrame('Isochronous Data', self.startTime, frame.end_time, {'PAR_LEN': PAR_LEN, 'data':bytes(self.receiveBuffer[4:]), 'message': bytes(self.receiveBuffer)})
						self.receive_buffer_pointer = -1
			
			if frame.start_time - self.startTime > (frame.end_time-frame.start_time) * 400:
				tempMSG = AnalyzerFrame('error', self.startTime, frame.end_time, {'error': 'Timeout'})
				self.receive_buffer_pointer = -1
			self.receive_buffer_pointer += 1;
			if (self.receive_buffer_pointer == 0):
				return tempMSG

