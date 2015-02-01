// Dictionary of functions used by the HTTP handler

package dictionary

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jfindley/skds/config"
	"github.com/jfindley/skds/messages"
	"github.com/jfindley/skds/server/auth"

	admin "github.com/jfindley/skds/admin/functions"
	server "github.com/jfindley/skds/server/functions"
)

// The Serverfn takes a pointer to the config object and a decoded message.
// It returns a status code and response data.
// The Adminfn takes a pointer to the config object and the commandline data
// It returns a response string and an error.
type ApiFunction struct {
	Serverfn     func(*config.Config, *auth.AuthObject, messages.Message) (int, messages.Message)
	Clientfn     func(*config.Config, string, []string) error
	AuthRequired bool
	AdminOnly    bool
	SuperOnly    bool
	AclCheck     bool
	Description  string
}

// Here we define a tree-like structure to establish command heirarchy
// It can be nested indefinitely, and doesn't require any sort of run-time
// reflection to parse.
// One tradeoff is that you cannot walk "up" the tree -  a child can never
// find out their parent.  This means we must always start at the root of
// the tree to build the URL for a function.

type Tree struct {
	Members  map[string]ApiFunction
	Children map[string]*Tree
}

var Group = Tree{
	Members: map[string]ApiFunction{
		"assign": AdminGroupAssign,
		"new":    AdminGroupNew,
		"delete": AdminGroupDel,
		"list":   AdminGroupList,
	},
}

var Admin = Tree{
	Members: map[string]ApiFunction{
		"password": AdminPass,
		"new":      AdminNew,
		"delete":   AdminDel,
		"super":    AdminSuper,
		"pubkey":   AdminPubkey,
		"list":     AdminList,
	},
	Children: map[string]*Tree{
		"group": &Group,
	},
}

var Client = Tree{
	Members: map[string]ApiFunction{
		"delete":   ClientDel,
		"group":    ClientGroup,
		"list":     ClientList,
		"register": ClientRegister,
		"keys":     ClientGetKey,
	},
}

var KeyAdmin = Tree{
	Members: map[string]ApiFunction{
		"assign": KeyAssignAdmin,
		"remove": KeyRemoveAdmin,
		"public": KeyPubAdmin,
		"super":  KeySuper,
		"list":   KeyListAdmin,
	},
}

var KeyClient = Tree{
	Members: map[string]ApiFunction{
		"assign": KeyAssignClient,
		"remove": KeyRemoveClient,
		"public": KeyPubClient,
		"list":   KeyListClient,
	},
}

var KeyGroup = Tree{
	Members: map[string]ApiFunction{
		"assign": KeyAssignGroup,
		"remove": KeyRemoveGroup,
		"public": KeyPubGroup,
		"list":   KeyListGroup,
	},
}

var Key = Tree{
	Members: map[string]ApiFunction{
		"list":   KeyList,
		"new":    KeyNew,
		"delete": KeyDel,
		"update": KeyUpdate,
	},
	Children: map[string]*Tree{
		"admin":  &KeyAdmin,
		"client": &KeyClient,
		"group":  &KeyGroup,
	},
}

var Dictionary = Tree{
	Members: map[string]ApiFunction{
		"ca":       GetCA,
		"setup":    Setup,
		"test":     Test,
		"testauth": TestAuth,
	},
	Children: map[string]*Tree{
		"admin":  &Admin,
		"client": &Client,
		"key":    &Key,
	},
}

// Misc functions

var GetCA = ApiFunction{
	Serverfn:    server.GetCA,
	Description: "Display the server CA",
}

var Test = ApiFunction{
	Serverfn:    server.Test,
	Clientfn:    admin.Test,
	Description: "Test function",
}

var TestAuth = ApiFunction{
	Serverfn:     server.Test,
	Clientfn:     admin.Test,
	AuthRequired: true,
	Description:  "Test function",
}

var Setup = ApiFunction{
	Serverfn:     server.Setup,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Create the group secret for the super-group",
}

// Admin functions

var AdminPass = ApiFunction{
	Serverfn:     server.AdminPass,
	Clientfn:     admin.Pass,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Change your admin password",
}

var AdminNew = ApiFunction{
	Serverfn:     server.AdminNew,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Create a new admin user",
}

var AdminDel = ApiFunction{
	Serverfn:     server.AdminDel,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Delete an admin user",
}

var AdminSuper = ApiFunction{
	Serverfn:     server.AdminSuper,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Change an admin's superuser status",
}

var AdminPubkey = ApiFunction{
	Serverfn:     server.AdminPubkey,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Set your pubkey as an admin",
}

var AdminList = ApiFunction{
	Serverfn:     server.AdminList,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "List all admins",
}

var AdminGroupNew = ApiFunction{
	Serverfn:     server.AdminGroupNew,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Create a new group",
}

var AdminGroupDel = ApiFunction{
	Serverfn:     server.AdminGroupDel,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Delete a group",
}

var AdminGroupList = ApiFunction{
	Serverfn:     server.AdminGroupList,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "list groups",
}

var AdminGroupAssign = ApiFunction{
	Serverfn:     server.AdminGroupAssign,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Assign an admin to a group",
}

// Client functions

var ClientGetKey = ApiFunction{
	Serverfn:     server.ClientGetKey,
	AuthRequired: true,
	Description:  "Download keys assigned to this client",
}

var ClientDel = ApiFunction{
	Serverfn:     server.ClientDel,
	AuthRequired: true,
	AdminOnly:    true,
	AclCheck:     true,
	Description:  "Delete a client",
}

var ClientGroup = ApiFunction{
	Serverfn:     server.ClientGroup,
	AuthRequired: true,
	AdminOnly:    true,
	AclCheck:     true,
	Description:  "Change a client's group",
}

var ClientRegister = ApiFunction{
	Serverfn:    server.ClientRegister,
	Description: "Register a new client",
}

var ClientList = ApiFunction{
	Serverfn:     server.ClientList,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "List all clients",
}

// Key functions

var KeyList = ApiFunction{
	Serverfn:     server.KeyList,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "list all keys",
}

var KeyPubClient = ApiFunction{
	Serverfn:     server.KeyPubClient,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Download the public key for a client",
}

var KeyPubAdmin = ApiFunction{
	Serverfn:     server.KeyPubAdmin,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Download the public key for an admin",
}

var KeySuper = ApiFunction{
	Serverfn:     server.KeySuper,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Download the public key for the super-group",
}

var KeyPubGroup = ApiFunction{
	Serverfn:     server.KeyPubGroup,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Download the public key for a group",
}

var KeyPrivGroup = ApiFunction{
	Serverfn:     server.KeyPrivGroup,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Download the (encrypted with the super-key) private key for a group",
}

var KeyNew = ApiFunction{
	Serverfn:     server.KeyNew,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Add a new key",
}

var KeyDel = ApiFunction{
	Serverfn:     server.KeyDel,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Delete a key",
}

var KeyUpdate = ApiFunction{
	Serverfn:     server.KeyUpdate,
	AuthRequired: true,
	AdminOnly:    true,
	Description:  "Update the data of a secret",
}

var KeyAssignAdmin = ApiFunction{
	Serverfn:     server.KeyAssignAdmin,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Assign a key to an admin",
}

var KeyAssignClient = ApiFunction{
	Serverfn:     server.KeyAssignClient,
	AuthRequired: true,
	AdminOnly:    true,
	AclCheck:     true,
	Description:  "Assign a key to a client",
}

var KeyAssignGroup = ApiFunction{
	Serverfn:     server.KeyAssignGroup,
	AuthRequired: true,
	AdminOnly:    true,
	AclCheck:     true,
	Description:  "Assign a key to a group",
}

var KeyRemoveAdmin = ApiFunction{
	Serverfn:     server.KeyRemoveAdmin,
	AuthRequired: true,
	AdminOnly:    true,
	SuperOnly:    true,
	Description:  "Remove a key from an admin",
}

var KeyRemoveClient = ApiFunction{
	Serverfn:     server.KeyRemoveClient,
	AuthRequired: true,
	AdminOnly:    true,
	AclCheck:     true,
	Description:  "Remove a key from a client",
}

var KeyRemoveGroup = ApiFunction{
	Serverfn:     server.KeyRemoveGroup,
	AuthRequired: true,
	AdminOnly:    true,
	AclCheck:     true,
	Description:  "Remove a key from a group",
}

var KeyListAdmin = ApiFunction{
	Serverfn:     server.KeyListAdmin,
	AuthRequired: true,
	AdminOnly:    true,
	AclCheck:     true,
	Description:  "List all keys for an admin",
}

var KeyListClient = ApiFunction{
	Serverfn:     server.KeyListClient,
	AuthRequired: true,
	AdminOnly:    true,
	AclCheck:     true,
	Description:  "List all keys for a client",
}

var KeyListGroup = ApiFunction{
	Serverfn:     server.KeyListGroup,
	AuthRequired: true,
	AdminOnly:    true,
	AclCheck:     true,
	Description:  "List all keys for a group",
}

func (t *Tree) urlMap(base string) map[string]ApiFunction {
	urls := make(map[string]ApiFunction)
	for name, fn := range t.Members {
		urls[fmt.Sprintf("%s/%s", base, name)] = fn
	}
	for name, child := range t.Children {
		c := child // Clone this so it doesn't get overwritten
		childurls := c.urlMap(fmt.Sprintf("%s/%s", base, name))
		for n, f := range childurls {
			urls[n] = f
		}
	}
	return urls
}

func (t *Tree) descMap(base string) map[string]string {
	out := make(map[string]string)
	for name, fn := range t.Members {
		out[fmt.Sprintf("%s %s", base, name)] = fn.Description
	}
	for name, child := range t.Children {
		c := child
		childout := c.descMap(fmt.Sprintf("%s %s", base, name))
		for n, f := range childout {
			out[n] = f
		}
	}
	return out
}

func (t *Tree) URLDict() map[string]ApiFunction {
	return t.urlMap("")
}

func (t *Tree) Docs() {
	docs := t.descMap("")
	output := make([]string, len(docs))
	var i int
	for path, desc := range docs {
		output[i] = fmt.Sprintf("%s%s%s", path[1:], strings.Repeat(" ", 29-len(path)), desc)
		i++
	}
	sort.Strings(output)
	fmt.Println(strings.Join(output, "\n"))
	return
}

func (t *Tree) FindFunc(cfg *config.Config, input []string) error {
	treeref := t
	var url string
	for i, in := range input {
		if _, ok := treeref.Members[in]; ok {
			if treeref.Members[in].Clientfn == nil {
				return errors.New("Sorry, this function is not available currently.  If you feel you need it, please file a bug.")
			}
			// Found a valid function, build the URL and run it (with data if present)
			var data []string
			if len(input) > i {
				data = input[i+1:]
			}
			url = fmt.Sprintf("%s/%s", url, in)
			return treeref.Members[in].Clientfn(cfg, url, data)
		}
		if _, ok := treeref.Children[in]; ok {
			// Found a subtree.  Move treeref.
			url = fmt.Sprintf("%s/%s", url, in)
			treeref = treeref.Children[in]
		}
	}
	// Invalid input, print docs for as far as we got
	treeref.Docs()
	return nil
}
