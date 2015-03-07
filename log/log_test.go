package log

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"
)

func TestStart(t *testing.T) {
	tmpfile, err := ioutil.TempFile(os.TempDir(), "skds_log_test")
	if err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	defer os.Remove(tmpfile.Name())

	var l Logger

	err = l.Start(ERROR, tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	err = l.Stop()
	if err != nil {
		t.Fatal(err)
	}

	err = l.Start(ERROR, "")
	if err != nil {
		t.Fatal(err)
	}

	if l.fh != os.Stdout {
		t.Error("Bad log file")
	}
}

func TestWrite(t *testing.T) {
	tmpfile, err := ioutil.TempFile(os.TempDir(), "skds_log_test")
	if err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	defer os.Remove(tmpfile.Name())

	var l Logger

	err = l.Start(INFO, tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	l.Log(ERROR, "error")
	l.Log(WARN, "warn")
	l.Log(INFO, "info")
	l.Log(DEBUG, "debug")

	err = l.Stop()
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte("error\nwarn\ninfo\n")

	contents, err := ioutil.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(contents, expected) != 0 {
		t.Errorf("Log data mismatch.  Expected: %s, Got: %s\n", expected, contents)
	}

}
