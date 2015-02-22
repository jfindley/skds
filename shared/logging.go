package shared

import (
	"fmt"
	"io/ioutil"
	"os"
)

// TODO: Re-do this library.  Maybe using a third-party solution.

var prefixes = map[int]string{
	-1: "",
	0:  "ERROR: ",
	1:  "WARN: ",
	2:  "INFO: ",
	3:  "DEBUG: ",
}

type LogItem struct {
	Message string
	Level   int
}

func Verbosity(o int) Option {
	return func(c *Config) {
		c.Startup.LogLevel = o
	}
}

func LogFile() Option {
	return func(c *Config) {
		if c.Startup.LogFile != "STDOUT" {
			f, err := os.Open(c.Startup.LogFile)
			if err != nil {
				// Cannot write to log, discard logs instead
				c.Runtime.Log = ioutil.Discard
			} else {
				c.Runtime.Log = f
			}
		} else {
			c.Runtime.Log = os.Stdout
		}
	}
}

func (c *Config) Log(level int, values ...interface{}) {
	if c.Runtime.Log == nil {
		c.Option(LogFile())
	}
	pref, ok := prefixes[level]
	if !ok {
		pref = ""
	}
	if level <= c.Startup.LogLevel {
		_, err := fmt.Fprintln(c.Runtime.Log, pref, values)
		if err != nil {
			fmt.Println("Logging error:", err)
		}
	}
}

// No log level for fatal errors - these are always shown
func (c *Config) Fatal(values ...interface{}) {
	if c.Runtime.Log == nil {
		c.Option(LogFile())
	}
	_, err := fmt.Fprintln(c.Runtime.Log, "FATAL: ", values)
	if err != nil {
		fmt.Println("Logging error:", err)
	}
	os.Exit(1)
}
