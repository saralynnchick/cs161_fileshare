package proj2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestGetUser(t *testing.T) {
	clear()
	userlib.SetDebugStatus(true)
	// normal init and get
	alice, err := InitUser("alice", "password")
	if err != nil {
		t.Error("User init failed", err)
		return
	}
	alice2, err := GetUser("alice", "password")
	if err != nil {
		t.Error("User get failed", err)
		return
	}
	t.Log("user2", alice2)
	t.Log("1", alice)
	if !reflect.DeepEqual(alice, alice2) {
		t.Error("users not the same", alice, alice2)
		return
	}
}

func TestSomeMoreShares(t *testing.T) {
	clear()
	u1, err := InitUser("u1", "a")
	if err != nil {
		t.Error(err)
		return
	}
	u2, err := InitUser("u2", "b")
	if err != nil {
		t.Error(err)
		return
	}
	u3, err := InitUser("u3", "c")
	if err != nil {
		t.Error(err)
		return
	}
	u4, err := InitUser("u4", "d")
	if err != nil {
		t.Error(err)
		return
	}

	u1.StoreFile("f1", []byte("test shit"))
	if err != nil {
		t.Error(err)
		return
	}
	token, err := u1.ShareFile("f1", "u2")
	if err != nil {
		t.Error(err)
		return
	}

	err = u2.ReceiveFile("u2-f1", "u1", token)
	if err != nil {
		t.Error(err)
		return
	}

	token, err = u2.ShareFile("u2-f1", "u3")
	if err != nil {
		t.Error(err)
		return
	}

	err = u3.ReceiveFile("u3-f1", "u2", token)
	if err != nil {
		t.Error(err)
		return
	}

	token, err = u3.ShareFile("u3-f1", "u4")
	if err != nil {
		t.Error(err)
		return
	}
	err = u4.ReceiveFile("u4-f1", "u3", token)
	f1, err := u1.LoadFile("f1")
	if err != nil {
		t.Error(err)
		return
	}
	f4, err := u4.LoadFile("u4-f1")
	if err != nil {
		t.Error(err)
		return
	}

	if !reflect.DeepEqual(f1, f4) {
		t.Error("files didn't match")
		return
	}
	u4.AppendFile("u4-f1", []byte("L"))
	f1, err = u1.LoadFile("f1")
	if err != nil {
		t.Error(err)
		return
	}
	f4, err = u4.LoadFile("u4-f1")
	if err != nil {
		t.Error(err)
		return
	}

	if !reflect.DeepEqual(f1, f4) {
		t.Error("files didn't match")
		return
	}
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestAppend(t *testing.T) {
	clear()
	bob, err := InitUser("bob", "password")
	if err != nil {
		t.Error("User init failed", err)
		return
	}

	v1 := []byte("dulll")
	bob.StoreFile("f1", v1)
	vvs, err := bob.LoadFile("f1")
	if err != nil {
		t.Error("load file failed 1", err)
		return
	}
	if !reflect.DeepEqual(v1, vvs) {
		t.Error("file not same", v1, vvs)
		return
	}

	appendData := []byte("uv")
	err = bob.AppendFile("f1", appendData)
	if err != nil {
		t.Error("append failed", err)
		return
	}
	data := append(v1, appendData...)
	svvs, err := bob.LoadFile("f1")
	if err != nil {
		t.Error("load after append failed", err)
		return
	}
	if !reflect.DeepEqual(svvs, data) {
		t.Error("file not same", svvs, data)
		return
	}

}

func TestOverwrite(t *testing.T) {
	clear()
	a, _ := InitUser("alice", "fubar")
	b, _ := InitUser("bob", "lame")
	a.StoreFile("f1", []byte("yadig"))
	a.StoreFile("f2", []byte("lmao"))
	a.StoreFile("f1", []byte("lmao"))
	a.StoreFile("f3", []byte("skrt"))

	f1, _ := a.LoadFile("f1")
	f2, _ := a.LoadFile("f2")
	if !reflect.DeepEqual(f1, f2) {
		t.Error("files diff")
		return
	}

	accessToken, _ := a.ShareFile("f1", "bob")

	b.ReceiveFile("bf1", "alice", accessToken)
	b.StoreFile("bf1", []byte("skrt"))
	ft, _ := b.LoadFile("bf1")
	f3, _ := a.LoadFile("f3")
	if !reflect.DeepEqual(ft, f3) {
		t.Error("files diff")
		return
	}
	// ft, _ = a.LoadFile("f1")
	// if !reflect.DeepEqual(ft, f3) {
	// 	t.Error("files diff")
	// 	return
	// }

}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestInvalidateDataStore(t *testing.T) {
	clear()
	// valid := true
	ds := userlib.DatastoreGetMap()
	a, err := InitUser("al", "pw")
	if err != nil {
		t.Error("we messed up init")
	}
	a.StoreFile("file1", []byte("yoyoyo"))
	for key, _ := range ds {
		ds[key] = []byte("lol bruh")
	}

	_, err = a.LoadFile("file1")
	if err == nil {
		t.Error("we should have failed mate")
	}
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}
