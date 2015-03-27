// +build linux darwin

package main

import (
	"github.com/codegangsta/cli"
	"os/user"
	"testing"

	"github.com/jfindley/skds/dictionary"
	"github.com/jfindley/skds/shared"
)

func TestCommandTree(t *testing.T) {
	dict := make(map[string]dictionary.APIFunc)
	cfg := new(shared.Config)

	// Valid is an apifunc with a valid adminfn.
	// Invalid is an apifinc without a valid adminfn.
	// We should only see valid apifuncs in the final output.
	var valid dictionary.APIFunc
	var invalid dictionary.APIFunc

	valid.Adminfn = func(cfg *shared.Config, ctx *cli.Context, url string) bool {
		return true
	}

	dict["/valid/sub/f1"] = valid
	dict["/valid/sub/f2"] = valid
	dict["/invalid/f3"] = invalid

	app := commandTree(cfg, dict)

	if len(app.Commands) != 1 {
		t.Fatal("Bad number of root commands")
	}

	if app.Commands[0].Name != "valid" {
		t.Error("Root command has bad name:", app.Commands[0].Name)
	}

	if len(app.Commands[0].Subcommands) != 1 {
		t.Fatal("Bad number of subcommands")
	}

	if app.Commands[0].Subcommands[0].Name != "sub" {
		t.Error("Subcommand has bad name:", app.Commands[0].Name)
	}

	if len(app.Commands[0].Subcommands[0].Subcommands) != 2 {
		t.Fatal("Bad number of actions")
	}

	for _, cmd := range app.Commands[0].Subcommands[0].Subcommands {
		if cmd.Name != "f1" && cmd.Name != "f2" {
			t.Error("Action has bad name:", cmd.Name)
		}
	}
}

func TestCommandSplitter(t *testing.T) {
	usr, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

	input := `arg1     arg2 "arg 3" arg\"4 ~/arg5 'arg " 6'`
	expected := []string{appname, "arg1", "arg2", "arg 3", "arg\"4", usr.HomeDir + "/arg5", "arg \" 6"}

	out := commandSplitter(input)

	if len(out) != len(expected) {
		t.Fatal("Bad output length")
	}

	for i := range out {
		if out[i] != expected[i] {
			t.Error("Mismatched output:", out[i], expected[i])
		}
	}
}
