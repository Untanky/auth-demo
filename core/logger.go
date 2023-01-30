package core

type Logger interface {
	Critical(message any)
	Error(message any)
	Warn(message any)
	Info(message any)
	Debug(message any)
	Verbose(message any)
}
