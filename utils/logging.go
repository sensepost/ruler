package utils

import (
	"io"
	"log"
)

var (
	Trace   *log.Logger
	Info    *log.Logger
	Fail    *log.Logger
	Warning *log.Logger
	Error   *log.Logger
)

//Init the logging function
func Init(
	traceHandle io.Writer,
	infoHandle io.Writer,
	warningHandle io.Writer,
	errorHandle io.Writer) {

	Trace = log.New(traceHandle, "[*] ", 0)
	Info = log.New(infoHandle, "[+] ", 0)
	Fail = log.New(infoHandle, "[x] ", 0)
	Warning = log.New(warningHandle,
		"[WARNING] ", 0)

	Error = log.New(errorHandle,
		"ERROR: ", log.Ldate|log.Ltime)
}
