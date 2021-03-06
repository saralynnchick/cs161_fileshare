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

	//

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// pkeEncryption on the sharing struct instead of symmetric
//share sends a uuid which is where the signed and encrypted shareFile struct exists.

type shareFile struct {
	// Og       uuid.UUID
	FileCont uuid.UUID
	EncKey   []byte
	HmacKey  []byte
}

type File struct {
	Head uuid.UUID
	Tail uuid.UUID
}

type FileNode struct {
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
	if err != nil {
		return nil, errors.New("pkey failed for some reason")
	}
	userdata.RSAPrivKey = privKey
	userdata.RSAPubKey = pubKey
	userdata.FileEncrypt = make(map[string][]byte)
	userdata.FileHMAC = make(map[string][]byte)
	userdata.FileLocation = make(map[string]userlib.UUID)
	userdata.HMAC_Key, err = userlib.HMACEval(unhashedStoredKey, []byte(password))
	if err != nil {
		return nil, errors.New("hmac failed to return a tag")
	}
	id := bytesToUUID(unhashedStoredKey)
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
	if err != nil {
		return nil, errors.New("marshal failed")
	}
	encrypted_marshal := userlib.SymEnc(unhashedStoredKey, userlib.RandomBytes(userlib.AESBlockSizeBytes), pad(marshaledData))
	user_data_tag, err := userlib.HMACEval(unhashedStoredKey, encrypted_marshal)
	if err != nil {
		return nil, errors.New("hmac failed to return a tag")
	}
	hidden_data := append(user_data_tag, encrypted_marshal...)
	// userlib.KeystoreSet(username+"rsa", pubKey)
	userlib.KeystoreSet(username, userdata.RSAPubKey)
	// println(pubKey.PubKey.N.String())
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

	if len(hidden_data) <= userlib.HashSizeBytes {
		return nil, errors.New("bad data, can't slice getuser")
	}

	hmac_tag := hidden_data[:userlib.HashSizeBytes]
	hidden_user := hidden_data[userlib.HashSizeBytes:]
	if len(unhashedStoredKey) != 16 {
		return nil, errors.New("hmac failed in getuser")
	}
	probe_hidden_user, err := userlib.HMACEval(unhashedStoredKey, hidden_user)
	if err != nil {
		return nil, errors.New("hmac failed in getuser")
	}
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
	var file_data FileNode
	var file_container File
	var container_uuid userlib.UUID
	//TODO: This is a toy implementation.
	if userdata == nil {
		return errors.New("userdata nil")
	}
	file_data.Data = data
	file_data.Next = bytesToUUID([]byte("nullnullnullnull"))

	// _, exists := userdata.FileLocation[filename]
	file_enc := userlib.RandomBytes(userlib.AESKeySizeBytes)
	file_hmac := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 16)
	// file_hmac := userlib.Argon2Key(userlib.RandomBytes(userlib.AESKeySizeBytes), userlib.RandomBytes(userlib.AESKeySizeBytes), 16)
	_, ok := userdata.FileLocation[filename]
	if !ok {
		container_uuid = uuid.New()
		userdata.FileLocation[filename] = container_uuid
	}
	container_uuid = userdata.FileLocation[filename]

	file_uuid := uuid.New()

	file_container.Head = file_uuid
	file_container.Tail = file_uuid

	userdata.FileEncrypt[filename] = file_enc
	userdata.FileHMAC[filename] = file_hmac

	marshaled_file, err := json.Marshal(file_data)
	if err != nil {
		return errors.New("store file failed marshal")
	}

	encryptedFile := userlib.SymEnc(file_enc, userlib.RandomBytes(userlib.AESBlockSizeBytes), pad(marshaled_file))
	file_tag, err := userlib.HMACEval(file_hmac, encryptedFile)
	if err != nil {
		return errors.New("store file failed hmac eval")
	}
	hidden_file := append(file_tag, encryptedFile...)

	userlib.DatastoreSet(file_uuid, hidden_file)

	mashaled_cont, err := json.Marshal(file_container)
	if err != nil {
		return errors.New("store file failed marshal")
	}
	encryptedCont := userlib.SymEnc(file_enc, userlib.RandomBytes(userlib.AESBlockSizeBytes), pad(mashaled_cont))
	cont_tag, err := userlib.HMACEval(file_hmac, encryptedCont)
	if err != nil {
		return errors.New("store file failed hmac eval")
	}
	hidden_cont := append(cont_tag, encryptedCont...)

	// storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	// jsonData, _ := json.Marshal(data)
	userlib.DatastoreSet(userdata.FileLocation[filename], hidden_cont)
	//End of toy implementation
	updateUser(userdata)

	return
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	var file_container File
	var old_tail FileNode
	var new_tail FileNode

	if userdata == nil {
		return errors.New("userdata nil")
	}
	hidden_cont, ok := userlib.DatastoreGet(userdata.FileLocation[filename])

	if !ok {
		return errors.New("what are we appending")
	}
	if len(hidden_cont) <= userlib.HashSizeBytes {
		return errors.New("bad data, can't slice getuser")
	}
	hmac_tag := hidden_cont[:userlib.HashSizeBytes]
	hidden_data := hidden_cont[userlib.HashSizeBytes:]
	if len(userdata.FileHMAC[filename]) != 16 {
		return errors.New("our probe key a bad length, user corrupted")
	}

	probe_hmac, err := userlib.HMACEval(userdata.FileHMAC[filename], hidden_data)

	if err != nil {
		return errors.New("probe line failed in appendfile")
	}

	if !userlib.HMACEqual(hmac_tag, probe_hmac) {
		return errors.New("Data seems to be corrupted")
	}

	encKey := userdata.FileEncrypt[filename]

	err = json.Unmarshal(depad(userlib.SymDec(encKey, hidden_data)), &file_container)

	hidden_tail, v := userlib.DatastoreGet(file_container.Tail)
	if !v {
		return errors.New("datastore get failed in append")
	}
	if len(hidden_tail) <= userlib.HashSizeBytes {
		return errors.New("bad data, can't slice getuser")
	}
	hmac_tag = hidden_tail[:userlib.HashSizeBytes]
	hidden_data = hidden_tail[userlib.HashSizeBytes:]
	if len(userdata.FileHMAC[filename]) != 16 {
		return errors.New("Probe without proper key in load")
	}
	probe_hmac, err = userlib.HMACEval(userdata.FileHMAC[filename], hidden_data)

	if err != nil {
		return errors.New("probe line failed in appendfile")
	}
	if !userlib.HMACEqual(hmac_tag, probe_hmac) {
		return errors.New("Thy data seemeth to beith corrupted")
	}

	err = json.Unmarshal(depad(userlib.SymDec(encKey, hidden_data)), &old_tail)
	if err != nil {
		return errors.New("unmarshal failed in append")
	}
	new_node_uuid := uuid.New()

	old_tail.Next = new_node_uuid

	marshaled_tail, err := json.Marshal(old_tail)
	if err != nil {
		return errors.New("marshal failed in append")
	}
	encrypted_tail := userlib.SymEnc(encKey, userlib.RandomBytes(userlib.AESBlockSizeBytes), pad(marshaled_tail))
	tail_tag, err := userlib.HMACEval(userdata.FileHMAC[filename], encrypted_tail)
	if err != nil {
		return errors.New("hmac eval failed in appendfile")
	}
	hidden_tail = append(tail_tag, encrypted_tail...)
	userlib.DatastoreSet(file_container.Tail, hidden_tail)

	file_container.Tail = new_node_uuid
	new_tail.Data = data

	marshaled_tail, err = json.Marshal(new_tail)
	if err != nil {
		return errors.New("marshal failed in append")
	}
	encrypted_tail = userlib.SymEnc(encKey, userlib.RandomBytes(userlib.AESBlockSizeBytes), pad(marshaled_tail))
	tail_tag, err = userlib.HMACEval(userdata.FileHMAC[filename], encrypted_tail)
	if err != nil {
		return errors.New("hmac eval failed in appendfile")
	}
	hidden_tail = append(tail_tag, encrypted_tail...)
	userlib.DatastoreSet(new_node_uuid, hidden_tail)

	marshaled_cont, err := json.Marshal(file_container)
	if err != nil {
		return errors.New("marshal failed in append")
	}
	encrypted_cont := userlib.SymEnc(encKey, userlib.RandomBytes(userlib.AESBlockSizeBytes), pad(marshaled_cont))
	cont_tag, err := userlib.HMACEval(userdata.FileHMAC[filename], encrypted_cont)
	if err != nil {
		return errors.New("hmac eval failed in appendfile")
	}
	hidden_cont = append(cont_tag, encrypted_cont...)
	userlib.DatastoreSet(userdata.FileLocation[filename], hidden_cont)

	return
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {

	var file_data FileNode
	var file_container File
	if userdata == nil {
		return nil, errors.New("userdata nil")
	}
	//TODO: This is a toy implementation.
	hidden_c, ok := userlib.DatastoreGet(userdata.FileLocation[filename])
	// print(hidden_c)

	if !ok {
		return nil, errors.New("The filename doesn't exist for this user")
	}
	if len(hidden_c) <= userlib.HashSizeBytes {
		return nil, errors.New("bad data, can't slice getuser")
	}
	hmac_tag := hidden_c[:userlib.HashSizeBytes]
	hidden_cont := hidden_c[userlib.HashSizeBytes:]
	if len(userdata.FileHMAC[filename]) != 16 {
		return nil, errors.New("Probe without proper key in load")
	}
	probe_hmac, err := userlib.HMACEval(userdata.FileHMAC[filename], hidden_cont)
	if err != nil {
		return nil, errors.New("probing in load failed")
	}
	if !userlib.HMACEqual(hmac_tag, probe_hmac) {
		return nil, errors.New("Data seems to be corrupted")
	}

	encKey := userdata.FileEncrypt[filename]

	err = json.Unmarshal(depad(userlib.SymDec(encKey, hidden_cont)), &file_container)
	if err != nil {
		return nil, errors.New("unmarshaling failed")
	}
	hidden_file, ok := userlib.DatastoreGet(file_container.Head)
	if !ok {
		return nil, errors.New(" bad head yyyy")
	}
	if len(hidden_file) <= userlib.HashSizeBytes {
		return nil, errors.New("bad data, can't slice getuser")
	}
	hmac_tag = hidden_file[:userlib.HashSizeBytes]
	hidden_file = hidden_file[userlib.HashSizeBytes:]
	if len(userdata.FileHMAC[filename]) != 16 {
		return nil, errors.New("Probe without proper key in load")
	}
	probe_hmac, err = userlib.HMACEval(userdata.FileHMAC[filename], hidden_file)
	if err != nil {
		return nil, errors.New("probing in load failed")
	}
	if !userlib.HMACEqual(hmac_tag, probe_hmac) {
		return nil, errors.New("Data seems to be corrupted")
	}

	err = json.Unmarshal(depad(userlib.SymDec(encKey, hidden_file)), &file_data)
	if err != nil {
		return nil, errors.New("unmarshaling failed")
	}
	cur_id := file_container.Head

	for cur_id != file_container.Tail {
		hidden_file, ok := userlib.DatastoreGet(cur_id)
		if !ok {
			return nil, errors.New("what are we appending")
		}
		if len(hidden_file) <= userlib.HashSizeBytes {
			return nil, errors.New("bad data, can't slice getuser")
		}
		hmac_tag := hidden_file[:userlib.HashSizeBytes]
		hidden_data := hidden_file[userlib.HashSizeBytes:]
		if len(userdata.FileHMAC[filename]) != 16 {
			return nil, errors.New("Probe without proper key in load")
		}
		probe_hmac, err := userlib.HMACEval(userdata.FileHMAC[filename], hidden_data)
		if err != nil {
			return nil, errors.New("probing in load failed")
		}
		if !userlib.HMACEqual(hmac_tag, probe_hmac) {
			return nil, errors.New("Data seems to be corrupted")
		}

		encKey := userdata.FileEncrypt[filename]

		err = json.Unmarshal(depad(userlib.SymDec(encKey, hidden_data)), &file_data)
		if err != nil {
			return nil, errors.New("unmarshaling failed")
		}
		dataBytes = append(dataBytes, file_data.Data...)
		cur_id = file_data.Next
	}

	hidden_file, ok = userlib.DatastoreGet(cur_id)
	if !ok {
		return nil, errors.New("what are we appending")
	}
	if len(hidden_file) <= userlib.HashSizeBytes {
		return nil, errors.New("bad data, can't slice getuser")
	}
	hmac_tag = hidden_file[:userlib.HashSizeBytes]
	hidden_data := hidden_file[userlib.HashSizeBytes:]
	if len(userdata.FileHMAC[filename]) != 16 {
		return nil, errors.New("Probe without proper key in load")
	}
	probe_hmac, err = userlib.HMACEval(userdata.FileHMAC[filename], hidden_data)
	if err != nil {
		return nil, errors.New("probing in load failed")
	}
	if !userlib.HMACEqual(hmac_tag, probe_hmac) {
		return nil, errors.New("Data seems to be corrupted")
	}

	err = json.Unmarshal(depad(userlib.SymDec(encKey, hidden_data)), &file_data)
	if err != nil {
		return nil, errors.New("unmarshaling failed")
	}
	dataBytes = append(dataBytes, file_data.Data...)

	return dataBytes, nil
	//End of toy implementation

}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (accessToken uuid.UUID, err error) {

	var share_cont shareFile
	// share_cont.Og = userdata.UUID
	if userdata == nil {
		return uuid.New(), errors.New("userdata nil")
	}
	share_cont.FileCont = userdata.FileLocation[filename]
	share_cont.EncKey = userdata.FileEncrypt[filename]
	share_cont.HmacKey = userdata.FileHMAC[filename]

	shared_uuid := uuid.New()

	recipient_pubKey, ok := userlib.KeystoreGet(recipient)

	if !ok {
		return shared_uuid, errors.New("bad map yo")
	}

	//double check the implementation we have right here with marshalled and sigs we are sending
	//I think it breaks because we dont have the right order of signing and encrypting?
	// I think theres something else we have to remarshal bef
	sender_sig_key := userdata.Signature
	marshaled_share, err := json.Marshal(share_cont)
	if err != nil {
		return shared_uuid, errors.New("marshal fails")
	}

	encrypted_share, err := userlib.PKEEnc(recipient_pubKey, marshaled_share)
	if err != nil {
		return shared_uuid, errors.New("encryption failed")
	}
	signed_tag, err := userlib.DSSign(sender_sig_key, encrypted_share)
	if err != nil {
		return shared_uuid, errors.New("dssign in share failed")
	}
	share_camo := append(signed_tag, encrypted_share...)
	// println(recipient_pubKey.PubKey.N.String())

	userlib.DatastoreSet(shared_uuid, share_camo)

	return shared_uuid, nil
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {
	var encSharedData shareFile
	if userdata == nil {
		return errors.New("userdata nil")
	}
	hidden_share, ok := userlib.DatastoreGet(accessToken)
	if !ok {
		return errors.New("we f'd up")
	}
	sender_publickey, ok := userlib.KeystoreGet(sender + "sig_ver")
	if !ok {
		return errors.New("we f'd up pt.2 with getting sender key")
	}
	//verify the file and decrypt
	if len(hidden_share) <= 256 {
		return errors.New("bad data, can't slice getuser")
	}
	sign_tag := hidden_share[:256]
	encrypted_data := hidden_share[256:]
	// print(encrypted_data)
	err := userlib.DSVerify(sender_publickey, encrypted_data, sign_tag)
	if err != nil {
		return errors.New("Done messed up verifying")
	}
	fileDecrypted, err := userlib.PKEDec(userdata.RSAPrivKey, encrypted_data)
	if err != nil {
		return errors.New("bad decryption")
	}
	//resend user struct
	err = json.Unmarshal(fileDecrypted, &encSharedData)
	if err != nil {
		return errors.New("Done messed up unmarshalling")
	}

	userdata.FileLocation[filename] = encSharedData.FileCont
	userdata.FileEncrypt[filename] = encSharedData.EncKey
	userdata.FileHMAC[filename] = encSharedData.HmacKey

	//re-encrypt user stuff
	//I think we just need to use the helper function we created to reencrypt at this part and reupload to server
	//but sharing file part has to be figured out first.
	return nil
}

//helper function to re-encrypt and sign (for updating on server)
func updateUser(userdata *User) {
	unhashedStoredKey := userlib.Argon2Key([]byte(userdata.Username), []byte(userdata.Password), 16)
	marshaledData, _ := json.Marshal(userdata)
	encrypted_marshal := userlib.SymEnc(unhashedStoredKey, userlib.RandomBytes(userlib.AESBlockSizeBytes), pad(marshaledData))
	user_data_tag, _ := userlib.HMACEval(unhashedStoredKey, encrypted_marshal)
	hidden_data := append(user_data_tag, encrypted_marshal...)
	userlib.DatastoreSet(bytesToUUID(unhashedStoredKey), hidden_data)
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {

	// curr_file, ok := userdata.FileLocation[filename]
	// if !ok {
	// 	return errors.New("Revoke done messed up")
	// }
	// curr_stored_data, ok := userlib.DataStoreGet(//get current main file from data storage)
	//decrypt data from the files we just got both hmac and symdec?
	//unmarshal data
	//verify signatures/came from original source
	//unmarshal sigs??
	//verify priv keys??

	return

}
