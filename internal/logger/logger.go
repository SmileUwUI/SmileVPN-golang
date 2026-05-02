package logger

import (
	"log"
)

const (
	LogLevelError = 1
	LogLevelInfo  = 2
	LogLevelDebug = 3
	LogLevelTrace = 4
)

const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorReset  = "\033[0m"
)

type Logger struct {
	level int
}

func NewLogger(level int) *Logger {
	return &Logger{level: level}
}

func (l *Logger) Error(format string, v ...interface{}) {
	if l.level >= LogLevelError {
		log.Printf(colorRed+"[ERROR] "+format+colorReset, v...)
	}
}

func (l *Logger) Info(format string, v ...interface{}) {
	if l.level >= LogLevelInfo {
		log.Printf(colorGreen+"[INFO]  "+format+colorReset, v...)
	}
}

func (l *Logger) Debug(format string, v ...interface{}) {
	if l.level >= LogLevelDebug {
		log.Printf(colorCyan+"[DEBUG] "+format+colorReset, v...)
	}
}

func (l *Logger) Trace(format string, v ...interface{}) {
	if l.level >= LogLevelTrace {
		log.Printf(colorBlue+"[TRACE] "+format+colorReset, v...)
	}
}
