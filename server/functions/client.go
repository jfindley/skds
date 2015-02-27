/*
Functions specifies a list of server functions, split out into different files based on API tree.
Because the description of each function already exists in the dictionary package, until such a time
as the dictionary is removed, the purpose of a function will be documented in the dictionary package,
not here.
We do, however document the message we expect to recieve for each function.  All input messages are
shared.Message messages.
*/
package functions

import (
	"github.com/jfindley/skds/server/auth"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

/*
No input
*/
func ClientGetKey(cfg *shared.Config, r shared.Request) {
	list := make([]shared.Message, 0)

	if authobj.GID != shared.DefClientGID {
		rows, err := cfg.DB.Table("group_secrets").Where("group_secrets.gid = ?", authobj.GID).Select(
			"group_secrets.secret, master_secrets.secret, group_secrets.path",
		).Joins("left join master_secrets on group_secrets.sid = master_secrets.id").Rows()
		if err != nil {
			println(err.Error())
			return genericFailure(cfg, err)
		}

		for rows.Next() {
			var (
				m            shared.Message
				groupSecret  []byte
				masterSecret []byte
				path         string
			)
			err = rows.Scan(&groupSecret, &masterSecret, &path)
			if err != nil {
				println(err.Error())
				return genericFailure(cfg, err)
			}
			m.Key.Secret = masterSecret
			m.Key.Key = groupSecret
			m.Key.Path = path
			list = append(list, m)
		}
	}

	rows, err := cfg.DB.Table("client_secrets").Where("client_secrets.uid = ?", authobj.UID).Select(
		"client_secrets.secret, master_secrets.secret, client_secrets.path",
	).Joins("left join master_secrets on client_secrets.sid = master_secrets.id").Rows()
	if err != nil {
		println(err.Error())
		return genericFailure(cfg, err)
	}

	for rows.Next() {
		var (
			m            shared.Message
			clientSecret []byte
			masterSecret []byte
			path         string
		)
		err = rows.Scan(&clientSecret, &masterSecret, &path)
		if err != nil {
			println(err.Error())
			return genericFailure(cfg, err)
		}
		m.Key.Secret = masterSecret
		m.Key.Key = clientSecret
		m.Key.Path = path
		list = append(list, m)
	}

	resp.Response = "OK"
	resp.ResponseData = list
	return
}

/*
Client.Name => Name
*/
func ClientDel(cfg *shared.Config, r shared.Request) {
	q := cfg.DB.Where("name = ?", msg.Client.Name).Delete(db.Users{})
	if q.RecordNotFound() {
		resp.Response = "No such user"
		ret = 404
		return
	} else if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}
	resp.Response = "OK"
	return
}

/*
Client.Name => name
Client.Group => name of group
Key.GroupPriv => Copy of the group private key, encrypted with the public key of the target client
*/
func ClientGroup(cfg *shared.Config, r shared.Request) {
	// This function relies on the client sending a pre-computed group key.
	// We can't do this on the server as it would involve having the ability to decrypt keys.

	if msg.Key.GroupPriv == nil && msg.Client.Group != "default" {
		return namedFailure(400, "No group key provided, unable to assign group")
	}

	client := new(db.Users)
	group := new(db.Groups)

	q := cfg.DB.Where("name = ?", msg.Client.Name).First(client)
	if q.RecordNotFound() {
		return namedFailure(400, "No such client")
	} else if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}

	q = cfg.DB.Where("name = ? and kind = ?", msg.Client.Group, "client").First(group)
	if q.RecordNotFound() {
		return namedFailure(400, "No such group")
	} else if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}

	if client.GID == group.Id {
		return namedFailure(200, "Client already member of this group")
	}

	client.GID = group.Id

	if msg.Client.Group == "default" {
		client.GroupKey = nil
	} else {
		client.GroupKey = shared.HexEncode(msg.Key.GroupPriv)
	}

	q = cfg.DB.Save(client)
	if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}
	resp.Response = "OK"
	return
}

/*
Client.Name => name
Client.Password => encrypted password
Client.Key => public part of local key
*/
func ClientRegister(cfg *shared.Config, r shared.Request) {
	client := new(db.Users)

	client.Name = msg.Client.Name
	client.Password = shared.HexEncode(msg.Client.Password)
	client.Pubkey = shared.HexEncode(msg.Client.Key)
	client.GID = shared.DefClientGID

	if cfg.DB.First(client).RecordNotFound() {
		q := cfg.DB.Create(client)
		if q.Error != nil {
			return genericFailure(cfg, q.Error)
		}
	} else {
		resp.Response = "Client with this name already exists"
		return 401, resp
	}

	resp.Response = "OK"
	return
}

/*
No input
*/
func ClientList(cfg *shared.Config, r shared.Request) {
	list := make([]shared.Message, 0)

	rows, err := cfg.DB.Table("clients").Select("clients.name, groups.name").Joins("left join groups on clients.gid = groups.id").Rows()
	if err != nil {
		return genericFailure(cfg, err)
	}

	for rows.Next() {
		var m shared.Message
		err = rows.Scan(&m.Client.Name, &m.Client.Group)
		if err != nil {
			return genericFailure(cfg, err)
		}
		list = append(list, m)
	}
	resp.ResponseData = list
	resp.Response = "OK"
	return
}
