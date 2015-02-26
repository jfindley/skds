package functions

import (
    "github.com/jfindley/skds/config"
    "github.com/jfindley/skds/transport"
)

func Test(cfg *config.Config, url string, input []string) (err error) {
    resp, err := transport.Request(cfg, url, nil)
    if err != nil {
        return
    }
    cfg.Log(-1, resp.Response)
    return
}
