package shared

import (
	"bytes"
	"github.com/jinzhu/gorm"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jfindley/skds/crypto"
)

var testData = []byte(`{
    "Auth": {
        "Name": "admin"
    }
}`)

type closingBuffer struct {
	*bytes.Buffer
}

func (cb closingBuffer) Close() error {
	crypto.Zero(cb.Bytes())
	return nil
}

type mockSession struct{}

func (s *mockSession) CheckACL(db gorm.DB, objects ...ACL) bool {
	return true
}

func (s *mockSession) NextKey() crypto.Binary {
	return []byte("123456")
}

func (s *mockSession) GetName() string {
	return "admin"
}

func (s *mockSession) GetUID() uint {
	return 1
}

func (s *mockSession) GetGID() uint {
	return 3
}

func (s *mockSession) IsAdmin() bool {
	return true
}

func (s *mockSession) IsSuper() bool {
	return true
}

func TestResponseNew(t *testing.T) {
	headers := make(map[string][]string)
	headers["test"] = []string{"one", "two"}

	in := &closingBuffer{bytes.NewBuffer(testData)}
	req := new(http.Request)
	req.Body = *in
	req.Header = headers

	var r Request
	var resp http.ResponseWriter

	err := r.New(req, resp)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(r.Body, testData) != 0 {
		t.Error("Body does not match input")
	}

	for h := range headers {
		if _, ok := r.Headers[h]; !ok {
			t.Error("Missing header", h)
			continue
		}

		if len(headers[h]) != len(r.Headers[h]) {
			t.Error("Wrong number of elements in header", h)
			continue
		}

		for v := range headers[h] {
			if headers[h][v] != r.Headers[h][v] {
				t.Error("Mismatched headers")
			}
		}
	}
}

func TestResponseParse(t *testing.T) {
	in := &closingBuffer{bytes.NewBuffer(testData)}
	req := new(http.Request)
	req.Body = *in

	var r Request
	var resp http.ResponseWriter

	err := r.New(req, resp)
	if err != nil {
		t.Fatal(err)
	}

	err = r.Parse()
	if err != nil {
		t.Fatal(err)
	}

	if r.Req.Auth.Name != "admin" {
		t.Error("Did not successfully parse response")
	}
}

func TestResponseReply(t *testing.T) {
	in := &closingBuffer{bytes.NewBuffer(testData)}
	req := new(http.Request)
	req.Body = *in

	var r Request
	rec := httptest.NewRecorder()

	err := r.New(req, rec)
	if err != nil {
		t.Fatal(err)
	}

	session := new(mockSession)

	r.Session = session

	message := Message{Response: "OK"}

	r.Reply(200, message)

	if rec.Code != 200 {
		t.Error("Response not 200")
	}

	resp, err := ReadResp(rec.Body)
	if err != nil {

	}

	if len(resp) != 1 {
		t.Fatal("Wrong message count:", len(resp))
	}

	if message.Response != resp[0].Response {
		t.Error("Message sent does not match")
	}

	if len(rec.Header().Get(HdrKey)) == 0 {
		t.Error("Missing session key header")
	}
}

func TestResponseReplyMultiple(t *testing.T) {
	in := &closingBuffer{bytes.NewBuffer(testData)}
	req := new(http.Request)
	req.Body = *in

	var r Request
	rec := httptest.NewRecorder()

	err := r.New(req, rec)
	if err != nil {
		t.Fatal(err)
	}

	message := Message{Response: "OK"}

	r.Reply(200, message, message, message)

	if rec.Code != 200 {
		t.Error("Response not 200")
	}

	resp, err := ReadResp(rec.Body)
	if err != nil {

	}

	if len(resp) != 3 {
		t.Fatal("Wrong message count:", len(resp))
	}

	if message.Response != resp[0].Response {
		t.Error("Message sent does not match")
	}
}
