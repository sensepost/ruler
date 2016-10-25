package rpchttp

//All taken from https://github.com/openchange/openchange/blob/master/python/openchange/utils/packets.py

const (
	PFC_FIRST_FRAG          = 1
	PFC_LAST_FRAG           = 2
	PFC_PENDING_CANCEL      = 4
	PFC_SUPPORT_HEADER_SIGN = 4
	PFC_RESERVED_1          = 8
	PFC_CONC_MPX            = 16
	PFC_DID_NOT_EXECUTE     = 32
	PFC_MAYBE               = 64
	PFC_OBJECT_UUID         = 128
)

//as defined in dcerpc.idl
const (
	DCERPC_PKT_REQUEST    = 0
	DCERPC_PKT_PING       = 1
	DCERPC_PKT_RESPONSE   = 2
	DCERPC_PKT_FAULT      = 3
	DCERPC_PKT_WORKING    = 4
	DCERPC_PKT_NOCALL     = 5
	DCERPC_PKT_REJECT     = 6
	DCERPC_PKT_ACK        = 7
	DCERPC_PKT_CL_CANCEL  = 8
	DCERPC_PKT_FACK       = 9
	DCERPC_PKT_CANCEL_ACK = 10
	DCERPC_PKT_BIND       = 11
	DCERPC_PKT_BIND_ACK   = 12
	DCERPC_PKT_BIND_NAK   = 13
	DCERPC_PKT_ALTER      = 14
	DCERPC_PKT_ALTER_RESP = 15
	DCERPC_PKT_AUTH_3     = 16
	DCERPC_PKT_SHUTDOWN   = 17
	DCERPC_PKT_CO_CANCEL  = 18
	DCERPC_PKT_ORPHANED   = 19
	DCERPC_PKT_RTS        = 20
)

//RTS Flags
const (
	RTS_FLAG_NONE            = 0
	RTS_FLAG_PING            = 1
	RTS_FLAG_OTHER_CMD       = 2
	RTS_FLAG_RECYCLE_CHANNEL = 4
	RTS_FLAG_IN_CHANNEL      = 8
	RTS_FLAG_OUT_CHANNEL     = 0x10
	RTS_FLAG_EOF             = 0x20
	RTS_FLAG_ECHO            = 0x40
)

//RTS CMD
const (
	RTS_CMD_RECEIVE_WINDOW_SIZE      = 0
	RTS_CMD_FLOW_CONTROL_ACK         = 1
	RTS_CMD_CONNECTION_TIMEOUT       = 2
	RTS_CMD_COOKIE                   = 3
	RTS_CMD_CHANNEL_LIFETIME         = 4
	RTS_CMD_CLIENT_KEEPALIVE         = 5
	RTS_CMD_VERSION                  = 6
	RTS_CMD_EMPTY                    = 7
	RTS_CMD_PADDING                  = 8
	RTS_CMD_NEGATIVE_ANCE            = 9
	RTS_CMD_ANCE                     = 10
	RTS_CMD_CLIENT_ADDRESS           = 11
	RTS_CMD_ASSOCIATION_GROUP_ID     = 12
	RTS_CMD_DESTINATION              = 13
	RTS_CMD_PING_TRAFFIC_SENT_NOTIFY = 14
	RTS_CMD_CUSTOM_OUT               = 15
)

const (
	RPC_C_AUTHN_NONE                = 0x0
	RPC_C_AUTHN_GSS_NEGOTIATE       = 0x9  // SPNEGO
	RPC_C_AUTHN_WINNT               = 0xa  // NTLM
	RPC_C_AUTHN_GSS_SCHANNEL        = 0xe  // TLS
	RPC_C_AUTHN_GSS_KERBEROS        = 0x10 // Kerberos
	RPC_C_AUTHN_NETLOGON            = 0x44 // Netlogon
	RPC_C_AUTHN_DEFAULT             = 0xff // (NTLM)
	RPC_C_AUTHN_LEVEL_DEFAULT       = 0
	RPC_C_AUTHN_LEVEL_NONE          = 1
	RPC_C_AUTHN_LEVEL_CONNECT       = 2
	RPC_C_AUTHN_LEVEL_CALL          = 3
	RPC_C_AUTHN_LEVEL_PKT           = 4
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 5
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY   = 6
)
