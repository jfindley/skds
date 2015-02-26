package functions

import (
    "code.google.com/p/gopass"

    "github.com/jfindley/skds/config"
    "github.com/jfindley/skds/crypto"
    "github.com/jfindley/skds/messages"
    "github.com/jfindley/skds/transport"
)

func Pass(cfg *config.Config, url string, input []string) (err error) {
    var p1, p2 string
    for {
        p1, err = gopass.GetPass("Enter a new password: ")
        if err != nil {
            return
        }
        p2, err = gopass.GetPass("Confirm the new password: ")
        if err != nil {
            return
        }
        if p1 == p2 {
            break
        }
    }
    var msg messages.Message
    newpass, err := crypto.PasswordHash([]byte(p1))
    if err != nil {
        return
    }
    msg.Admin.Password = newpass
    _, err = transport.Request(cfg, url, msg)
    return
}
