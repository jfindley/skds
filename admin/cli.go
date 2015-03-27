// +build linux darwin
// +build 386

package main

import (
	"bufio"
	"github.com/codegangsta/cli"
	"os"
	"os/signal"
	"os/user"
	"sort"
	"strings"
	"syscall"

	"github.com/jfindley/skds/dictionary"
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/shared"
)

const appname string = "SKDS"

var usr *user.User

func init() {
	var err error
	usr, err = user.Current()
	if err != nil {
		panic(err)
	}

}

func startCli(cfg *shared.Config) {
	var err error

	sigs := make(chan os.Signal, 1)

	go func() {
		<-sigs
		cfg.Session.Logout(cfg)
		os.Exit(0)
	}()

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	scanner := bufio.NewScanner(os.Stdin)

	app := commandTree(cfg, dictionary.Dictionary)

	for scanner.Scan() {
		if scanner.Text() == "exit" || scanner.Text() == "quit" {
			err = cfg.Session.Logout(cfg)
			if err != nil {
				cfg.Log(log.ERROR, err)
			}
			os.Exit(0)
		}

		app.Run(commandSplitter(scanner.Text()))

	}
}

// This function walks through the functions in supplied dictionary to create a cli.App
// object.
func commandTree(cfg *shared.Config, dict map[string]dictionary.APIFunc) *cli.App {
	app := cli.NewApp()

	app.Name = appname
	app.Usage = "Admin console"

	var urls []string
	for url := range dict {
		urls = append(urls, url)
	}

	sort.Strings(urls)

	for _, url := range urls {

		// Copy this reference so it does not get overwritten
		api := dict[url]

		// We're only interested if an admin function exists
		if api.Adminfn == nil {
			continue
		}

		// Trim leading slashes to avoid the first element being blank.
		terms := strings.Split(strings.TrimPrefix(url, "/"), "/")

		// We use this as a pointer to the current path in the tree, which
		// is updated every time we go down a level into a new level of
		// subcommands.
		var prevCmd *cli.Command

	TERMWALKER:
		for i := range terms {

			name := strings.ToLower(terms[i])
			var cmd cli.Command

			// We have to handle the root commands differently, as cli.App
			// does not have a Subcommands field, and cli.Commands does not
			// have a Commands field.  This leads to quite a bit of uglyness.
			// It would be possible to condense this into a single function
			// using interfaces, but that would make the below code even less
			// readable.
			if i == 0 {

				// We're at the root of the tree, so can operate on app directly,
				// without copying an address and assigning it back later.

				if i == len(terms)-1 {
					// We are at the end of the tree, add the actual api function.
					cmd = api.CliFunc(cfg, url)
					cmd.Name = name

					app.Commands = append(app.Commands, cmd)

					break TERMWALKER
				}

				exists := false

				for c := range app.Commands {
					if app.Commands[c].Name == name {
						// Subcommand already exists.  Move prevCmd down a level
						// and continue with the next term.
						exists = true
						prevCmd = &app.Commands[c]
						break
					}
				}

				if !exists {
					// Create a subcommand in the tree.
					cmd.Name = name
					cmd.Usage = name + " commands"

					app.Commands = append(app.Commands, cmd)

					// Move prevCmd to the new subcommand we just created, and
					// go to the next term.
					prevCmd = &app.Commands[len(app.Commands)-1]

				}

			} else {

				// Use a working copy of the current command, as we append to it,
				// which changes the address.  We assign this back to prevCmd later.
				thisCmd := *prevCmd

				if i == len(terms)-1 {
					// We are at the end of the tree, add the actual api function.
					cmd = api.CliFunc(cfg, url)
					cmd.Name = name

					thisCmd.Subcommands = append(thisCmd.Subcommands, cmd)

					// Assign the working command back to the real tree
					*prevCmd = thisCmd

					break TERMWALKER
				}

				exists := false

				for c := range thisCmd.Subcommands {
					if thisCmd.Subcommands[c].Name == name {
						// Subcommand already exists.  Move prevCmd down a level
						// and continue with the next term.
						exists = true
						prevCmd = &thisCmd.Subcommands[c]
						break
					}
				}

				if !exists {
					// Create a subcommand in the tree.
					cmd.Name = name
					cmd.Usage = name + " commands"

					thisCmd.Subcommands = append(thisCmd.Subcommands, cmd)
					// Assign the working command back to the real tree
					*prevCmd = thisCmd

					// Move prevCmd to the new subcommand we just created, and
					// go to the next term.
					prevCmd = &thisCmd.Subcommands[len(thisCmd.Subcommands)-1]
				}

			}

		}

	}

	return app
}

// We prefix all commands with appname to keep the cli app happy.
func commandSplitter(in string) (out []string) {
	out = append(out, appname)
	var prev uint8
	var word string
	var isInQuote bool
	var singleQuote bool

	for i := 0; i < len(in); i++ {

		// Don't process escaped chars, just add to current word.
		if prev == '\\' {
			prev = in[i]
			word = word + string(in[i])
			continue
		}

		// Don't process or include escape characters.
		if in[i] == '\\' {
			prev = in[i]
			continue
		}

		prev = in[i]

		switch in[i] {

		case '~':
			if !singleQuote {
				word = word + usr.HomeDir
			}

		case '"':
			if !isInQuote {
				isInQuote = true
			} else if !singleQuote {
				isInQuote = false
				out = append(out, word)
				word = ""
			} else {
				word = word + string(in[i])
			}

		case '\'':
			if !isInQuote {
				isInQuote = true
				singleQuote = true
			} else if singleQuote {
				isInQuote = false
				out = append(out, word)
				word = ""
			} else {
				word = word + string(in[i])
			}

		case ' ':
			if !isInQuote && len(word) > 0 {
				// Wordsplit
				out = append(out, word)
				word = ""
			} else if isInQuote {
				word = word + string(in[i])
			}

		default:
			word = word + string(in[i])

		}

	}
	if len(word) > 0 {
		out = append(out, word)
	}
	return
}
