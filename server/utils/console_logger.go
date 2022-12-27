package utils

import (
	"fmt"
	"time"
)

type ConsoleLogger struct{}

func (logger *ConsoleLogger) Log(level string, message any) {
	fmt.Println(fmt.Sprintf("[%s] - %s", level, time.Now().UTC()), message)
}

func (logger *ConsoleLogger) Critical(message any) {
	logger.Log("Critical", message)
}

func (logger *ConsoleLogger) Error(message any) {
	logger.Log("Error", message)
}

func (logger *ConsoleLogger) Warn(message any) {
	logger.Log("Warn", message)
}

func (logger *ConsoleLogger) Info(message any) {
	logger.Log("Info", message)
}

func (logger *ConsoleLogger) Debug(message any) {
	logger.Log("Debug", message)
}

func (logger *ConsoleLogger) Verbose(message any) {
	logger.Log("Verbose", message)
}
