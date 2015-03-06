// Dictionary of functions used by the HTTP handler

package dictionary

import (
	"github.com/jfindley/skds/shared"

	// admin "github.com/jfindley/skds/admin/functions"
	server "github.com/jfindley/skds/server/functions"
)

// APIFunc defines an API function.
type APIFunc struct {
	Serverfn     func(*shared.Config, shared.Request)         // Function called by the server
	Adminfn      func(*shared.Config, string, []string) error // Function called by the admin client
	AuthRequired bool
	AdminOnly    bool
	SuperOnly    bool
	Description  string
}

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

	"/key/public/get/user":   UserPubKey,
	"/key/public/get/group":  GroupPubKey,
	"/key/public/get/super":  SuperPubKey,
	"/key/public/set":        SetPubKey,
	"/key/private/get/group": GroupPrivKey,
	"/key/private/set/super": SetSuperKey,

	"/secret/create": SecretNew,
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

// Misc functions

var GetCA = APIFunc{
	Serverfn:    server.GetCA,
	Description: "Display the server CA",
}

// Admin functions

var AdminPass = APIFunc{
	Serverfn: server.UserPass,
	// Adminfn:      admin.Pass,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Change your password",
}

var AdminNew = APIFunc{
	Serverfn:     server.AdminNew,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Create a new admin user",
}

var UserDel = APIFunc{
	Serverfn:     server.UserDel,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Delete a user",
}

var AdminSuper = APIFunc{
	Serverfn:     server.AdminSuper,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Make an admin a superuser",
}

var SetPubKey = APIFunc{
	Serverfn:     server.SetPubkey,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Set your public key",
}

var UserList = APIFunc{
	Serverfn:     server.UserList,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "List users",
}

var GroupNew = APIFunc{
	Serverfn:     server.GroupNew,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Create a new group",
}

var GroupDel = APIFunc{
	Serverfn:     server.GroupDel,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Delete a group",
}

var GroupList = APIFunc{
	Serverfn:     server.GroupList,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "list groups",
}

var UserGroupAssign = APIFunc{
	Serverfn:     server.UserGroupAssign,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Assign an admin to a group",
}

var SetSuperKey = APIFunc{
	Serverfn:     server.SetSuperKey,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Set the group key for the super-group",
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

// Secret functions

var SecretList = APIFunc{
	Serverfn:     server.SecretList,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "list all keys",
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

var SecretNew = APIFunc{
	Serverfn:     server.SecretNew,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Add a new key",
}

var SecretDel = APIFunc{
	Serverfn:     server.SecretDel,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Delete a key",
}

var SecretUpdate = APIFunc{
	Serverfn:     server.SecretUpdate,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Update the data of a secret",
}

var SecretAssignUser = APIFunc{
	Serverfn:     server.SecretAssignUser,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Assign a key to a user",
}

var SecretAssignGroup = APIFunc{
	Serverfn:     server.SecretAssignGroup,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Assign a key to a group",
}

var SecretRemoveUser = APIFunc{
	Serverfn:     server.SecretRemoveUser,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Remove a key from a user",
}

var SecretRemoveGroup = APIFunc{
	Serverfn:     server.SecretRemoveGroup,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Remove a key from a group",
}

var SecretListUser = APIFunc{
	Serverfn:     server.SecretListUser,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "List all keys for a user",
}

var SecretListGroup = APIFunc{
	Serverfn:     server.SecretListGroup,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "List all keys for a group",
}
