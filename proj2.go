package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"github.com/cs161-staff/userlib"

	// The JSON library will be useful for serializing go structs.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/json.html.
	"encoding/json"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// The Datastore requires UUIDs to store key-value entries.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/uuid.html.
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// User is the structure definition for a user record.
type User struct {
	Username          string
	UUID              uuid.UUID
	UnhashedStoredKey []byte
	Password          string
	RSAPubKey         userlib.PKEEncKey
	RSAPrivKey        userlib.PKEDecKey
	HMAC_Key          []byte
	Signature         userlib.PrivateKeyType
	// FilePerms         map[string]FileMapVals
	FileLocation map[string]uuid.UUID
	FileEncrypt  map[string][]byte
	FileHMAC     map[string][]byte

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type FileContent struct {
	Data []byte
	Next userlib.UUID
}

// type FileMapVals struct {
// 	fileKey  []byte
// 	AESKey   []byte
// 	HMAC     []byte //lets see if these fix the bug for AES and HMAC key creation
// 	Location uuid.UUID
// }

//FIXME
//TODO
/* We need to marshal the data, then we need to encrypt it with symmetric key, so AES.
We then need to create some hmac/signature based off AES and append it to AES
We upload this to the data store. This represents signed, encrypted data.
Also in data store upload salted password for each username.
In get user we will check to see if user exists based on if the password they give matches
salted password we have in store for that user.
To retrieve their data, split the datastore value into the signature and AES encrypted stuff.
Check to see if signature matches the result of signing the AES part. If so data valid.
Decrypt AES, and unmarshal.
*/
func pad(toPad []byte) (res []byte) {

	offset := userlib.AESBlockSizeBytes - (len(toPad) % userlib.AESBlockSizeBytes)
	res = toPad
	for i := 0; i < offset; i++ {
		res = append(res, byte(offset))
	}
	return
}

func depad(toUnPad []byte) (res []byte) {
	res = toUnPad[:len(toUnPad)-int(toUnPad[len(toUnPad)-1])]
	return
}

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	// userdataptr = &userdata

	//TODO: This is a toy implementation.
	userdata.Username = username
	unhashedStoredKey := userlib.Argon2Key([]byte(username), []byte(password), 16)
	userdata.UnhashedStoredKey = unhashedStoredKey
	userdata.Password = password
	pubKey, privKey, err := userlib.PKEKeyGen()
	userdata.RSAPrivKey = privKey
	userdata.RSAPubKey = pubKey
	userdata.FileEncrypt = make(map[string][]byte)
	userdata.FileHMAC = make(map[string][]byte)
	userdata.FileLocation = make(map[string]userlib.UUID)
	userdata.HMAC_Key, _ = userlib.HMACEval(unhashedStoredKey, []byte(password))
	id := uuid.New()
	userdata.UUID = id
	// salt := []byte("yolo")
	// databasePassword := userlib.Argon2Key([]byte(password), salt, 16)
	// databasePassword := append(salt, password...)
	if err != nil {
		return nil, errors.New("Init User Struct: marshal userdata error") //keep on trucking through
	}

	sig, verify, err := userlib.DSKeyGen()
	// userdata.Signature = sig
	if err != nil {
		return nil, errors.New("Init User Struct: datastore error") //keep on trucking through
	}
	// uname := bytesToUUID([]byte(username))
	userdata.Signature = sig
	marshaledData, err := json.Marshal(userdata)
	encrypted_marshal := userlib.SymEnc(unhashedStoredKey, userlib.RandomBytes(userlib.AESBlockSizeBytes), pad(marshaledData))
	user_data_tag, _ := userlib.HMACEval(unhashedStoredKey, encrypted_marshal)
	hidden_data := append(user_data_tag, encrypted_marshal...)
	userlib.KeystoreSet(username+"rsa", pubKey)
	userlib.KeystoreSet(username, userdata.RSAPubKey)
	userlib.KeystoreSet(username+"sig_ver", verify)
	userlib.DatastoreSet(bytesToUUID(unhashedStoredKey), hidden_data)
	// userlib.DatastoreSet(uname, salt)
	//End of toy implementation

	return &userdata, nil

}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	_, ok := userlib.KeystoreGet(username)
	if !ok {
		return nil, errors.New("GetUser ERROR, public key is non-existent")
	}

	unhashedStoredKey := userlib.Argon2Key([]byte(username), []byte(password), 16)
	// HMAC_Key, _ := userlib.HMACEval(unhashedStoredKey, []byte(password))
	hidden_data, ok := userlib.DatastoreGet(bytesToUUID(unhashedStoredKey))

	if !ok {
		return nil, errors.New("Bad password username combo")
	}

	hmac_tag := hidden_data[:userlib.HashSizeBytes]
	hidden_user := hidden_data[userlib.HashSizeBytes:]

	probe_hidden_user, _ := userlib.HMACEval(unhashedStoredKey, hidden_user)
	if !userlib.HMACEqual(probe_hidden_user, hmac_tag) {
		return nil, errors.New("data for user seems to be corrupted")
	}

	err = json.Unmarshal(depad(userlib.SymDec(unhashedStoredKey, hidden_user)), userdataptr)
	if err != nil {
		return nil, errors.New("GetUser: unmarshal storedData unable to verify")
	}

	return userdataptr, nil
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	var file_data FileContent
	//TODO: This is a toy implementation.

	file_data.Data = data
	file_data.Next = bytesToUUID([]byte("nullnullnullnull"))

	_, exists := userdata.FileLocation[filename]
	file_enc := userlib.RandomBytes(userlib.AESKeySizeBytes)
	file_hmac := userlib.Argon2Key(userlib.RandomBytes(userlib.AESKeySizeBytes), userlib.RandomBytes(userlib.AESKeySizeBytes), 16)
	if !exists {
		file_uuid := uuid.New()

		userdata.FileLocation[filename] = file_uuid

	}

	userdata.FileEncrypt[filename] = file_enc
	userdata.FileHMAC[filename] = file_hmac

	marshaled_file, _ := json.Marshal(file_data)

	encryptedFile := userlib.SymEnc(file_enc, userlib.RandomBytes(userlib.AESBlockSizeBytes), pad(marshaled_file))
	file_tag, _ := userlib.HMACEval(file_hmac, encryptedFile)
	hidden_file := append(file_tag, encryptedFile...)

	// storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	// jsonData, _ := json.Marshal(data)
	userlib.DatastoreSet(userdata.FileLocation[filename], hidden_file)
	//End of toy implementation

	return
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	var cur_file_data FileContent
	var new_file_data FileContent

	hidden_file, ok := userlib.DatastoreGet(userdata.FileLocation[filename])

	if !ok {
		return errors.New("what are we appending")
	}
	hmac_tag := hidden_file[:userlib.HashSizeBytes]
	hidden_data := hidden_file[userlib.HashSizeBytes:]

	probe_hmac, _ := userlib.HMACEval(userdata.FileHMAC[filename], hidden_data)

	if !userlib.HMACEqual(hmac_tag, probe_hmac) {
		return errors.New("Data seems to be corrupted")
	}

	encKey := userdata.FileEncrypt[filename]

	err = json.Unmarshal(depad(userlib.SymDec(encKey, hidden_data)), &cur_file_data)
	old_id := userdata.FileLocation[filename]
	for cur_file_data.Next != bytesToUUID([]byte("null")) {
		hidden_file, ok := userlib.DatastoreGet(cur_file_data.Next)
		old_id = cur_file_data.Next
		if !ok {
			return errors.New("what are we appending")
		}
		hmac_tag := hidden_file[:userlib.HashSizeBytes]
		hidden_data := hidden_file[userlib.HashSizeBytes:]
		probe_hmac, _ := userlib.HMACEval(userdata.FileHMAC[filename], hidden_data)

		if !userlib.HMACEqual(hmac_tag, probe_hmac) {
			return errors.New("Data seems to be corrupted")
		}

		encKey := userdata.FileEncrypt[filename]

		err = json.Unmarshal(depad(userlib.SymDec(encKey, hidden_data)), &cur_file_data)
	}

	new_file_data.Data = data
	new_file_data.Next = bytesToUUID([]byte("null"))

	hmacKey := userdata.FileHMAC[filename]
	new_id := uuid.New()
	marshaled_file, _ := json.Marshal(new_file_data)
	encryptedFile := userlib.SymEnc(encKey, userlib.RandomBytes(userlib.AESBlockSizeBytes), pad(marshaled_file))
	file_tag, _ := userlib.HMACEval(hmacKey, encryptedFile)
	hidden_file = append(file_tag, encryptedFile...)
	userlib.DatastoreSet(new_id, hidden_file)

	cur_file_data.Next = new_id

	marshaled_file, _ = json.Marshal(cur_file_data)
	encryptedFile = userlib.SymEnc(encKey, userlib.RandomBytes(userlib.AESBlockSizeBytes), pad(marshaled_file))
	file_tag, _ = userlib.HMACEval(hmacKey, encryptedFile)
	hidden_file = append(file_tag, encryptedFile...)
	userlib.DatastoreSet(old_id, hidden_file)

	return
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {
	var file_data FileContent
	//TODO: This is a toy implementation.
	hidden_file, ok := userlib.DatastoreGet(userdata.FileLocation[filename])

	if !ok {
		return nil, errors.New("The filename doesn't exist for this user")
	}

	hmac_tag := hidden_file[:userlib.HashSizeBytes]
	hidden_data := hidden_file[userlib.HashSizeBytes:]

	probe_hmac, _ := userlib.HMACEval(userdata.FileHMAC[filename], hidden_data)

	if !userlib.HMACEqual(hmac_tag, probe_hmac) {
		return nil, errors.New("Data seems to be corrupted")
	}

	encKey := userdata.FileEncrypt[filename]

	err = json.Unmarshal(depad(userlib.SymDec(encKey, hidden_data)), &file_data)

	dataBytes = file_data.Data

	for file_data.Next != bytesToUUID([]byte("nullnullnullnull")) {
		hidden_file, ok := userlib.DatastoreGet(file_data.Next)
		if !ok {
			return nil, errors.New("what are we appending")
		}
		hmac_tag := hidden_file[:userlib.HashSizeBytes]
		hidden_data := hidden_file[userlib.HashSizeBytes:]
		probe_hmac, _ := userlib.HMACEval(userdata.FileHMAC[filename], hidden_data)

		if !userlib.HMACEqual(hmac_tag, probe_hmac) {
			return nil, errors.New("Data seems to be corrupted")
		}

		encKey := userdata.FileEncrypt[filename]

		err = json.Unmarshal(depad(userlib.SymDec(encKey, hidden_data)), &file_data)
		dataBytes = append(dataBytes, file_data.Data...)
	}

	return dataBytes, nil
	//End of toy implementation

}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {

	return
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {
	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	return
}
