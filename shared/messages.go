package shared

type Key struct {
	Name      string `json:",omitempty"`
	Client    string `json:",omitempty"`
	Admin     string `json:",omitempty"`
	Path      string `json:",omitempty"`
	Key       []byte `json:",omitempty"`
	Secret    []byte `json:",omitempty"`
	Userkey   []byte `json:",omitempty"`
	GroupPub  []byte `json:",omitempty"`
	GroupPriv []byte `json:",omitempty"`
}

type User struct {
	Name     string `json:",omitempty"`
	Admin    bool   `json:",omitempty"`
	Group    string `json:",omitempty"`
	Password []byte `json:",omitempty"`
	Key      []byte `json:",omitempty"`
}

type X509 struct {
	Name string `json:",omitempty"`
	Cert []byte `json:",omitempty"`
}

type Auth struct {
	Name     string `json:",omitempty"`
	Password []byte `json:",omitempty"`
}

type Message struct {
	Key      Key    `json:",omitempty"`
	User     User   `json:",omitempty"`
	X509     X509   `json:"x509,omitempty"`
	Auth     Auth   `json:",omitempty"`
	Response string `json:",omitempty"`
}
