package shared

import (
	"bytes"
	"github.com/jinzhu/gorm"
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

func TestResponseParse(t *testing.T) {
	var r Request
	rec := httptest.NewRecorder()

	if !r.Parse(testData, rec) {
		t.Fatal("Parse failed")
	}

	if r.Req.Auth.Name != "admin" {
		t.Error("Did not successfully parse response")
	}
}

func TestResponseReply(t *testing.T) {
	var r Request
	rec := httptest.NewRecorder()

	if !r.Parse(testData, rec) {
		t.Fatal("Parse failed")
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
	var r Request
	rec := httptest.NewRecorder()

	if !r.Parse(testData, rec) {
		t.Fatal("Parse failed")
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
