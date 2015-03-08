// Log is a very simple and lightweight level-based log package.
package log

import (
	"fmt"
	"os"
)

type LogLevel int

const (
	ERROR LogLevel = iota // 0
	WARN                  // 1
	INFO                  // 2
	DEBUG                 // 3
)

type Logger struct {
	fh    *os.File
	level LogLevel
}

// Start logging at given log level to file.
func (l *Logger) Start(level LogLevel, file string) (err error) {
	l.level = level
	if file == "" {
		l.fh = os.Stdout
	} else {
		l.fh, err = os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.FileMode(0660))
	}
	return
}

// Stop logging
func (l *Logger) Stop() (err error) {
	return l.fh.Close()
}

// Write log line at verbosity level.
func (l *Logger) Log(level LogLevel, values ...interface{}) {
	if level <= l.level {
		_, err := fmt.Fprintln(l.fh, values...)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Unable to write to logfile:", err)
		}
	}
	return
}

// Write to log and exit.
func (l *Logger) Fatal(values ...interface{}) {
	_, err := fmt.Fprintln(l.fh, values...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to write to logfile")
	} else {
		l.Stop()
	}
	os.Exit(1)
}
