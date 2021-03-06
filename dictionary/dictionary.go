// Dictionary of functions used by the HTTP handler and admin client
// Functions with a server component only are used internally but not called
// directly by an admin.
package dictionary

import (
	"github.com/codegangsta/cli"

	admin "github.com/jfindley/skds/admin/functions"
	"github.com/jfindley/skds/log"
	server "github.com/jfindley/skds/server/functions"
	"github.com/jfindley/skds/shared"
)

// APIFunc defines an API function.
type APIFunc struct {
	Serverfn     func(*shared.Config, shared.Request)            // Function called by the server
	Adminfn      func(*shared.Config, *cli.Context, string) bool // Function called by the admin client
	Flags        []cli.Flag                                      // CLI flags used by the admin client
	AuthRequired bool                                            // Authentication required
	AdminOnly    bool                                            // Admin clients only
	SuperOnly    bool                                            // Super users only
	Description  string                                          // Description of function
}

func (a *APIFunc) CliFunc(cfg *shared.Config, url string) (cmd cli.Command) {
	cmd.Usage = a.Description
	cmd.Flags = a.Flags

	cmd.Action = func(ctx *cli.Context) {
		ok := a.Adminfn(cfg, ctx, url)
		if ok {
			cfg.Log(log.INFO, "\nCommand complete\n\n")
		} else {
			cfg.Log(log.ERROR, "\nCommand failed\n\n")
		}
	}

	return
}

// Dictionary is a mapping of URL to function.
var Dictionary = map[string]APIFunc{
	"/admin/password": AdminPass,

	"/admin/user/create": AdminNew,
	"/admin/user/delete": UserDel,
	"/admin/user/list":   UserList,
	"/admin/user/super":  AdminSuper,
	"/admin/user/group":  UserGroupAssign,

	"/admin/group/create": GroupNew,
	"/admin/group/delete": GroupDel,
	"/admin/group/list":   GroupList,

	"/ca": GetCA,

	"/client/register": ClientRegister,
	"/client/secrets":  ClientGetSecret,

	"/key/public/get/user":    UserPubKey,
	"/key/public/get/group":   GroupPubKey,
	"/key/public/get/super":   SuperPubKey,
	"/key/public/get/secret":  SecretPubKey,
	"/key/public/set":         SetPubKey,
	"/key/private/get/group":  GroupPrivKey,
	"/key/private/get/secret": SecretPrivKey,
	"/key/private/set/super":  SetSuperKey,

	"/secret/create": SecretNew,
	"/secret/get":    SecretGet,
	"/secret/delete": SecretDel,
	"/secret/update": SecretUpdate,

	"/secret/list/all":   SecretList,
	"/secret/list/user":  SecretListUser,
	"/secret/list/group": SecretListGroup,

	"/secret/assign/user":  SecretAssignUser,
	"/secret/assign/group": SecretAssignGroup,

	"/secret/remove/user":  SecretRemoveUser,
	"/secret/remove/group": SecretRemoveGroup,
}

// Commonly used flags

var name = cli.StringFlag{Name: "name, n", Usage: "name"}
var group = cli.StringFlag{Name: "group, g", Usage: "group name"}
var secret = cli.StringFlag{Name: "secret, s", Usage: "secret name"}
var file = cli.StringFlag{Name: "file, f", Usage: "filename"}
var path = cli.StringFlag{Name: "path, p", Usage: "path secret will be saved at on clients"}
var isadmin = cli.BoolFlag{Name: "admin, a", Usage: "applies to admins, not clients"}

// Misc functions

// No adminfn as admin just uses the client version of this function.
var GetCA = APIFunc{
	Serverfn:    server.GetCA,
	Description: "Display the server CA",
}

// Admin functions

var AdminPass = APIFunc{
	Serverfn:     server.UserPass,
	Adminfn:      admin.Password,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Change your password",
}

var AdminNew = APIFunc{
	Serverfn:     server.AdminNew,
	Adminfn:      admin.AdminNew,
	Flags:        []cli.Flag{name},
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Create a new admin user",
}

var UserDel = APIFunc{
	Serverfn:     server.UserDel,
	Adminfn:      admin.UserDel,
	Flags:        []cli.Flag{name, isadmin},
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Delete a user",
}

var AdminSuper = APIFunc{
	Serverfn:     server.AdminSuper,
	Adminfn:      admin.AdminSuper,
	Flags:        []cli.Flag{name},
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Make an admin a superuser",
}

var UserList = APIFunc{
	Serverfn:     server.UserList,
	Adminfn:      admin.UserList,
	Flags:        []cli.Flag{isadmin},
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "List users",
}

var GroupNew = APIFunc{
	Serverfn:     server.GroupNew,
	Adminfn:      admin.GroupNew,
	Flags:        []cli.Flag{name, isadmin},
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Create a new group",
}

var GroupDel = APIFunc{
	Serverfn:     server.GroupDel,
	Adminfn:      admin.GroupDel,
	Flags:        []cli.Flag{name, isadmin},
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Delete a group",
}

var GroupList = APIFunc{
	Serverfn:     server.GroupList,
	Adminfn:      admin.GroupList,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "List groups",
}

var UserGroupAssign = APIFunc{
	Serverfn:     server.UserGroupAssign,
	Adminfn:      admin.UserGroupAssign,
	Flags:        []cli.Flag{name, isadmin, group},
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Assign a user to a group",
}

// Client functions

var ClientGetSecret = APIFunc{
	Serverfn:     server.ClientGetSecret,
	AuthRequired: true,
	Description:  "Download keys assigned to this client",
}

var ClientRegister = APIFunc{
	Serverfn:    server.ClientRegister,
	Description: "Register a new client",
}

// Key functions - these are rarely called directly, and are usually called
// as part of some other action.

var SetPubKey = APIFunc{
	Serverfn:     server.SetPubkey,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Set your public key",
}

var UserPubKey = APIFunc{
	Serverfn:     server.UserPubKey,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Download the public key for a user",
}

var SuperPubKey = APIFunc{
	Serverfn:     server.SuperPubKey,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Download the public key for the super-group",
}

var GroupPubKey = APIFunc{
	Serverfn:     server.GroupPubKey,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Download the public key for a group",
}

var GroupPrivKey = APIFunc{
	Serverfn:     server.GroupPrivKey,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Download the (encrypted with the super-key) private key for a group",
}

var SecretPubKey = APIFunc{
	Serverfn:     server.SecretPubKey,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Download the public key for a secret",
}

var SecretPrivKey = APIFunc{
	Serverfn:     server.SecretPrivKey,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Download the (encrypted) private key for a secret",
}

var SetSuperKey = APIFunc{
	Serverfn:     server.SetSuperKey,
	Adminfn:      admin.SetSuperKey,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Set the group key for the super-group",
}

// Secret functions

var SecretList = APIFunc{
	Serverfn:     server.SecretList,
	Adminfn:      admin.SecretList,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "list all secrets",
}

var SecretListUser = APIFunc{
	Serverfn:     server.SecretListUser,
	Adminfn:      admin.SecretListUser,
	Flags:        []cli.Flag{name, isadmin},
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "List all secrets for a user",
}

var SecretListGroup = APIFunc{
	Serverfn:     server.SecretListGroup,
	Adminfn:      admin.SecretListUser,
	Flags:        []cli.Flag{name, isadmin},
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "List all secrets for a group",
}

var SecretNew = APIFunc{
	Serverfn:     server.SecretNew,
	Adminfn:      admin.SecretNew,
	Flags:        []cli.Flag{name, file},
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Add a new secret",
}

var SecretGet = APIFunc{
	Serverfn:     server.SecretGet,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Download a secret",
}

var SecretDel = APIFunc{
	Serverfn:     server.SecretDel,
	Adminfn:      admin.SecretDel,
	Flags:        []cli.Flag{name},
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Delete a secret",
}

var SecretUpdate = APIFunc{
	Serverfn:     server.SecretUpdate,
	Adminfn:      admin.SecretUpdate,
	Flags:        []cli.Flag{name, file},
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Update the data of a secret",
}

var SecretAssignUser = APIFunc{
	Serverfn:     server.SecretAssignUser,
	Adminfn:      admin.SecretAssignUser,
	Flags:        []cli.Flag{name, secret, isadmin, path},
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Assign a secret to a user",
}

var SecretAssignGroup = APIFunc{
	Serverfn:     server.SecretAssignGroup,
	Adminfn:      admin.SecretAssignGroup,
	Flags:        []cli.Flag{name, secret, isadmin, path},
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Assign a secret to a group",
}

var SecretRemoveUser = APIFunc{
	Serverfn:     server.SecretRemoveUser,
	Adminfn:      admin.SecretRemoveUser,
	Flags:        []cli.Flag{name, secret, isadmin},
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Remove a secret from a user",
}

var SecretRemoveGroup = APIFunc{
	Serverfn:     server.SecretRemoveGroup,
	Adminfn:      admin.SecretRemoveGroup,
	Flags:        []cli.Flag{name, secret, isadmin},
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Remove a secret from a group",
}
