package utils

import (
	"fmt"
	"time"
)

type ConsoleLogger struct{}

func (logger *ConsoleLogger) Log(level string, message any) {
	fmt.Println(fmt.Sprintf("[%s] %s |", level, time.Now().Format("2006-02-01 15:04:05")), message)
}

func (logger *ConsoleLogger) Critical(message any) {
	logger.Log("CRITICAL", message)
}

func (logger *ConsoleLogger) Error(message any) {
	logger.Log("ERROR", message)
}

func (logger *ConsoleLogger) Warn(message any) {
	logger.Log("WARNING", message)
}

func (logger *ConsoleLogger) Info(message any) {
	logger.Log("INFO", message)
}

func (logger *ConsoleLogger) Debug(message any) {
	logger.Log("DEBUG", message)
}

func (logger *ConsoleLogger) Verbose(message any) {
	logger.Log("VERBOSE", message)
}
