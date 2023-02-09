package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

/// These are the constants used for getting different keys from KeyStore for a user
/// The number of These keys are fixed for each user

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string

	BlobOpenEK userlib.PKEDecKey
	BlobOpenDS userlib.DSSignKey

	RSAPriv userlib.PKEDecKey
	Sign    userlib.DSSignKey

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type Opener struct {
	EncKey  []byte
	HMACKey []byte
	HMAC    []byte
}
type Blob struct {
	FileID     uuid.UUID
	FileOpen   uuid.UUID
	EK         userlib.PKEDecKey
	PK         userlib.PKEEncKey
	DS         userlib.DSSignKey
	VS         userlib.DSVerifyKey
	Childs     map[uuid.UUID][]byte
	DSVer      userlib.DSVerifyKey
	ParentBlob uuid.UUID
	ParentKey  []byte
}
type File struct {
	Head uuid.UUID
	Tail uuid.UUID
	EK   userlib.PKEDecKey
	PK   userlib.PKEEncKey
	DS   userlib.DSSignKey
	VS   userlib.DSVerifyKey
}

type MasterKey struct {
	ID  uuid.UUID
	Key []byte
}
type Master_Meta struct {
	OP  Opener
	Sig []byte
}
type Packet struct {
	BlobObj      Blob
	BlobOpener   []byte
	ParentOpener []byte
}
type PacketPtr struct {
	PacketID     uuid.UUID
	PacketOpener uuid.UUID
}

type Node struct {
	ID   uuid.UUID
	Key  Opener
	Next uuid.UUID
}

type Content struct {
	Cont []byte
}

//// The following functions are used to retrieve keys from Key store
const (
	VERIFYKEY = iota
	PUBLICKEY
	FILEMAPKEY
	KEYCHAINKEY
	BLOBOPENPK
	BLOBOPENVS
	INVPTRPK
	INVPTRVS
	BLOBINTEGVS
)

func getpubkeyHelper(k string) (key userlib.PublicKeyType, err error) {
	key, ok := userlib.KeystoreGet(k)
	if !ok {
		err = errors.New("no such verify key exists")
		return
	}
	return key, nil
}

func getVal(id int) string {
	switch id {
	case VERIFYKEY:
		return "VERIFYKEY"
	case PUBLICKEY:
		return "PUBLICKEY"
	case BLOBOPENPK:
		return "BLOBOPENPKE"
	case BLOBOPENVS:
		return "BLOBOPENVS"
	default:
		return ""
	}
}

func getPubKey(username string, id int) (key userlib.PublicKeyType, err error) {
	return getpubkeyHelper(username + getVal(id))
}

/// start of helper functions
func getOpener(keyID uuid.UUID, EK userlib.PKEDecKey, VS userlib.DSVerifyKey) (op Opener, err error) {
	masterEnc, ok := userlib.DatastoreGet(keyID)
	if !ok {
		err = errors.New("not found /masterEnc")
		return
	}
	masteDec, err := userlib.PKEDec(EK, masterEnc)
	if err != nil {
		return
	}
	var master MasterKey
	err = json.Unmarshal(masteDec, &master)
	if err != nil {
		return
	}

	metaByte, ok := userlib.DatastoreGet(master.ID)
	if !ok {
		err = errors.New("not found /metaEnc")
		return
	}
	metaDec := userlib.SymDec(master.Key, metaByte)
	var meta Master_Meta
	err = json.Unmarshal(metaDec, &meta)
	if err != nil {
		return
	}
	err = userlib.DSVerify(VS, masterEnc, meta.Sig)
	if err != nil {
		return
	}
	op = meta.OP
	return
}

func saveOpener(keyID uuid.UUID, opener Opener, PK userlib.PKEEncKey, DS userlib.DSSignKey) (err error) {
	var master MasterKey
	master.Key = genKey()
	master.ID = genID()

	var meta Master_Meta
	meta.OP = opener

	masteBytes, err := json.Marshal(master)
	if err != nil {
		return err
	}
	encMasterByte, err := userlib.PKEEnc(PK, masteBytes)
	if err != nil {
		return
	}
	meta.Sig, err = userlib.DSSign(DS, encMasterByte)
	if err != nil {
		return
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return
	}
	metaEnc := userlib.SymEnc(master.Key, genIV(), metaBytes)
	userlib.DatastoreSet(master.ID, metaEnc)
	userlib.DatastoreSet(keyID, encMasterByte)
	return
}

func genKey() []byte {
	return userlib.Argon2Key([]byte(uuid.NewString()), userlib.RandomBytes(userlib.HashSizeBytes), userlib.AESKeySizeBytes)
}

func genID() uuid.UUID {
	id := uuid.New()
	return id
}

func genName(filename string, name string) []byte {
	nameStr := userlib.Argon2Key([]byte(filename), []byte(name), userlib.AESKeySizeBytes)
	return nameStr
}

func blobID(filename string, username string) (uid uuid.UUID, err error) {
	name := genName(filename, username)
	uid, err = uuid.FromBytes(name)
	return
}

func blobOpenerID(uid uuid.UUID, username string) (iid uuid.UUID, err error) {
	idBytes := userlib.Argon2Key([]byte(uid.String()), []byte(username), userlib.AESKeySizeBytes)
	iid, err = uuid.FromBytes(idBytes)
	return iid, err
}

func getBlobOpener(blobID uuid.UUID, user User) (key []byte, err error) {
	id, err := blobOpenerID(blobID, user.Username)
	if err != nil {
		return
	}
	VS, err := getPubKey(user.Username, BLOBOPENVS)
	if err != nil {
		return
	}
	op, err := getOpener(id, user.BlobOpenEK, VS)
	if err != nil {
		return
	}
	return op.EncKey, nil
}

func saveBlobOpener(blobID uuid.UUID, key []byte, user User) (err error) {
	var op Opener
	op.EncKey = key
	id, err := blobOpenerID(blobID, user.Username)
	if err != nil {
		return
	}
	PK, err := getPubKey(user.Username, BLOBOPENPK)
	if err != nil {
		return
	}
	return saveOpener(id, op, PK, user.BlobOpenDS)
}

func partOpenerID(uid uuid.UUID, fileID uuid.UUID) (iid uuid.UUID, err error) {
	idBytes := userlib.Argon2Key([]byte(uid.String()), []byte(fileID.String()), userlib.AESKeySizeBytes)
	iid, err = uuid.FromBytes(idBytes)
	return iid, err
}

func getPartCloudKey(partID uuid.UUID, fileID uuid.UUID, file File) (op Opener, err error) {
	keyID, err := partOpenerID(partID, fileID)
	if err != nil {
		return
	}
	return getOpener(keyID, file.EK, file.VS)
}

func savePartCloudKey(partID uuid.UUID, fileID uuid.UUID, op Opener, file File) (err error) {
	opID, err := partOpenerID(partID, fileID)
	if err != nil {
		return
	}
	return saveOpener(opID, op, file.PK, file.DS)
}

func genIV() []byte {
	return userlib.RandomBytes(userlib.AESBlockSizeBytes)
}
func genOpener() Opener {
	var op Opener
	op.EncKey = genKey()
	op.HMACKey = genKey()
	return op
}

func saveBytes(cont []byte) (id uuid.UUID, err error) {
	id = genID()
	userlib.DatastoreSet(id, cont)
	return
}
func genOpUsingBytes(cont []byte) (op Opener, enc []byte, err error) {
	op = genOpener()
	enc = userlib.SymEnc(op.EncKey, genIV(), cont)
	op.HMAC, err = userlib.HashKDF(op.HMACKey, enc)
	return
}

func genNode(cont []byte, next uuid.UUID, iid uuid.UUID) (usrOP Opener, err error) {
	var node Node
	var enc []byte
	node.Next = next
	node.Key, enc, err = genOpUsingBytes(cont)
	if err != nil {
		return
	}
	node.ID, err = saveBytes(enc)
	if err != nil {
		return
	}
	// serialize node
	nodeByte, err := json.Marshal(node)
	if err != nil {
		return
	}
	usrOP, nodeEnc, err := genOpUsingBytes(nodeByte)
	if err != nil {
		return
	}
	userlib.DatastoreSet(iid, nodeEnc)
	return
}
func verifyAndDecrypt(data []byte, opener Opener) (dec []byte, err error) {
	hmac, err := userlib.HashKDF(opener.HMACKey, data)
	if err != nil {

		return
	}
	if !userlib.HMACEqual(hmac, opener.HMAC) {
		userlib.DebugMsg("hmac is : %x", hmac)
		userlib.DebugMsg("should be : %x", opener.HMAC)
		err = errors.New("HMACs dont match")
		return
	}
	dec = userlib.SymDec(opener.EncKey, data)
	return dec, err
}

func getNode(id uuid.UUID, opener Opener) (node Node, err error) {
	enc, ok := userlib.DatastoreGet(id)
	if !ok {
		err = errors.New("no such node exist")
		return
	}
	dec, err := verifyAndDecrypt(enc, opener)
	if err != nil {
		return
	}
	err = json.Unmarshal(dec, &node)
	return
}

func updateNode(node Node, opener *Opener, id uuid.UUID) error {
	bytes, err := json.Marshal(node)
	if err != nil {
		return err
	}
	enc := userlib.SymEnc(opener.EncKey, genIV(), bytes)
	opener.HMAC, err = userlib.HashKDF(opener.HMACKey, enc)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(id, enc)
	return nil
}

func getContFromNode(nid uuid.UUID, opener Opener) (cont []byte, next uuid.UUID, contID userlib.UUID, err error) {

	node, err := getNode(nid, opener)
	if err != nil {
		err = errors.New("check getNode func")
		return
	}
	cenc, ok := userlib.DatastoreGet(node.ID)
	if !ok {
		err = errors.New(" cenc getContFromNode Can not wrok")
		return
	}
	next = node.Next
	cont, err = verifyAndDecrypt(cenc, node.Key)
	contID = node.ID
	return
}

func getFileOpener(blob Blob) (Opener, error) {
	return getOpener(blob.FileOpen, blob.EK, blob.VS)
}

func saveFileOperner(blob Blob, op Opener) error {
	return saveOpener(blob.FileOpen, op, blob.PK, blob.DS)
}

func saveFileToBlob(file File, blob Blob) (err error) {
	dec, err := json.Marshal(file)
	if err != nil {
		return err
	}
	openr := genOpener()
	enc := userlib.SymEnc(openr.EncKey, genIV(), dec)
	openr.HMAC, err = userlib.HashKDF(openr.HMACKey, enc)
	if err != nil {
		return
	}
	err = saveFileOperner(blob, openr)
	userlib.DatastoreSet(blob.FileID, enc)
	return
}
func getFileFromBlob(blob Blob) (file File, err error) {
	enc, ok := userlib.DatastoreGet(blob.FileID)
	if !ok {
		err = errors.New("can not find")
		return
	}
	opener, err := getFileOpener(blob)
	if err != nil {
		return
	}
	dec, err := verifyAndDecrypt(enc, opener)
	if err != nil {
		return
	}
	err = json.Unmarshal(dec, &file)
	return
}
func getBlob(id uuid.UUID, opener []byte) (blob Blob, err error) {
	enc, ok := userlib.DatastoreGet(id)
	if !ok {
		err = errors.New("blob not in datastore")
		return
	}
	dec := userlib.SymDec(opener, enc)
	if err != nil {
		return
	}
	err = json.Unmarshal(dec, &blob)
	return
}

func saveBlob(blob Blob, opener []byte, id uuid.UUID) (err error) {
	dec, err := json.Marshal(blob)
	if err != nil {
		return
	}
	enc := userlib.SymEnc(opener, genIV(), dec)
	userlib.DatastoreSet(id, enc)
	return
}

/// End of Helper functions
// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	if len(username) == 0 {
		err = errors.New("empty string")
		return
	}
	var userdata User
	userdata.Username = username

	pubRSA, privRSA, err := userlib.PKEKeyGen()
	if err != nil {
		return
	}
	err = userlib.KeystoreSet(username+getVal(PUBLICKEY), pubRSA)
	if err != nil {
		return
	}
	sign, verify, err := userlib.DSKeyGen()
	if err != nil {
		return
	}
	err = userlib.KeystoreSet(username+getVal(VERIFYKEY), verify)
	if err != nil {
		return
	}
	userdata.RSAPriv = privRSA
	userdata.Sign = sign

	blobRSA, blobPriv, err := userlib.PKEKeyGen()
	if err != nil {
		return
	}
	err = userlib.KeystoreSet(username+getVal(BLOBOPENPK), blobRSA)
	userdata.BlobOpenEK = blobPriv
	if err != nil {
		return
	}

	sign, verify, err = userlib.DSKeyGen()
	if err != nil {
		return
	}
	err = userlib.KeystoreSet(username+getVal(BLOBOPENVS), verify)
	if err != nil {
		return
	}
	userdata.BlobOpenDS = sign

	id := userlib.Argon2Key([]byte(password), []byte(userdata.Username), userlib.AESKeySizeBytes)
	key := userlib.Argon2Key(id, []byte(userdata.Username), userlib.AESKeySizeBytes)

	mackey := userlib.Argon2Key(id, key, userlib.AESKeySizeBytes)
	macId := userlib.Argon2Key(mackey, key, userlib.AESKeySizeBytes)
	macEnc := userlib.Argon2Key(macId, mackey, userlib.AESKeySizeBytes)

	userByte, err := json.Marshal(userdata)
	if err != nil {
		return
	}
	encUser := userlib.SymEnc(key, genIV(), userByte)
	iid, err := uuid.FromBytes(id)
	if err != nil {
		return
	}
	_, ok := userlib.DatastoreGet(iid)
	if ok {
		err = errors.New("already have a user with taht name")
		return
	}
	var cont Content
	cont.Cont, err = userlib.HashKDF(mackey, encUser)
	if err != nil {
		return
	}
	macByte, err := json.Marshal(cont)
	if err != nil {
		return
	}
	encmac := userlib.SymEnc(macEnc, genIV(), macByte)

	macIID, err := uuid.FromBytes(macId)
	if err != nil {
		return
	}
	userlib.DatastoreSet(macIID, encmac)
	userlib.DatastoreSet(iid, encUser)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	id := userlib.Argon2Key([]byte(password), []byte(username), userlib.AESKeySizeBytes)
	key := userlib.Argon2Key(id, []byte(username), userlib.AESKeySizeBytes)

	mackey := userlib.Argon2Key(id, key, userlib.AESKeySizeBytes)
	macId := userlib.Argon2Key(mackey, key, userlib.AESKeySizeBytes)
	macEnc := userlib.Argon2Key(macId, mackey, userlib.AESKeySizeBytes)
	iid, err := uuid.FromBytes(id)
	if err != nil {
		return
	}
	usrEncBytes, ok := userlib.DatastoreGet(iid)
	if !ok {
		return nil, errors.New("user not found")
	}
	macUID, err := uuid.FromBytes(macId)
	if err != nil {
		return
	}

	macEncByteCont, ok := userlib.DatastoreGet(macUID)
	if !ok {
		return nil, errors.New("faied mac")
	}

	macDecByteCont := userlib.SymDec(macEnc, macEncByteCont)

	var mac Content
	err = json.Unmarshal(macDecByteCont, &mac)
	if err != nil {
		return
	}
	userMac, err := userlib.HashKDF(mackey, usrEncBytes)
	if err != nil {
		return nil, errors.New("can not cal hmac")
	}
	if !userlib.HMACEqual(mac.Cont, userMac) {
		return nil, errors.New("HMacs do not match")
	}

	usrDecBytes := userlib.SymDec(key, usrEncBytes)
	err = json.Unmarshal(usrDecBytes, &userdata)
	if err != nil {
		return
	}
	return &userdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	var file File
	file.DS, file.VS, err = userlib.DSKeyGen()
	if err != nil {
		return
	}
	file.PK, file.EK, err = userlib.PKEKeyGen()
	if err != nil {
		return
	}
	id := genID()

	usrOP, err := genNode(content, uuid.Nil, id)
	if err != nil {
		return err
	}
	file.Head = id
	file.Tail = id
	//file.KeyChain[id] = usrOP

	var blob Blob
	blob.Childs = make(map[uuid.UUID][]byte)
	blob.FileOpen = genID()

	blob.PK, blob.EK, err = userlib.PKEKeyGen()
	if err != nil {
		return
	}
	blob.DS, blob.VS, err = userlib.DSKeyGen()
	if err != nil {
		return
	}

	blob.FileID = genID()
	blob.ParentBlob = uuid.Nil
	err = savePartCloudKey(id, blob.FileID, usrOP, file)
	if err != nil {
		return
	}
	err = saveFileToBlob(file, blob)
	if err != nil {
		return
	}

	blobOpener := genKey()
	blobid, err := blobID(filename, userdata.Username)
	if err != nil {
		return
	}
	err = saveBlob(blob, blobOpener, blobid)
	if err != nil {
		return
	}
	//chain.Map[blobid] = blobOpener
	err = saveBlobOpener(blobid, blobOpener, *userdata)

	//files.Map[filename] = blobid
	return err
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	sid, err := blobID(filename, userdata.Username)
	if err != nil {
		err = errors.New("sid not found")
		return err
	}
	op, err := getBlobOpener(sid, *userdata)
	if err != nil {
		userlib.DebugMsg("op not found for : %x", sid)
		return errors.New("op not found for")
	}
	blob, err := getBlob(sid, op)
	if err != nil {
		return err
	}
	file, err := getFileFromBlob(blob)
	if err != nil {
		return err
	}
	prevTailID := file.Tail
	//prevTailOP := file.KeyChain[prevTailID]
	prevTailOP, err := getPartCloudKey(prevTailID, blob.FileID, file)
	if err != nil {
		return err
	}
	prevTail, err := getNode(prevTailID, prevTailOP)
	if err != nil {
		return err
	}
	newTailID := genID()
	newTailOP, err := genNode(content, uuid.Nil, newTailID)
	if err != nil {
		return err
	}

	// add newTailOP to file
	//file.KeyChain[newTailID] = newTailOP
	err = savePartCloudKey(newTailID, blob.FileID, newTailOP, file)
	if err != nil {
		return err
	}
	// update prev tail then update keychain
	prevTail.Next = newTailID
	err = updateNode(prevTail, &prevTailOP, prevTailID)
	if err != nil {
		return err
	}
	//file.KeyChain[prevTailID] = prevTailOP
	err = savePartCloudKey(prevTailID, blob.FileID, prevTailOP, file)
	if err != nil {
		return err
	}
	// update file
	file.Tail = newTailID
	saveBlob(blob, op, sid)
	saveFileToBlob(file, blob)
	//chain.Map[sid] = op
	err = saveBlobOpener(sid, op, *userdata)
	//err = savKeyChain(userdata.KeyChainEnc, chain, userdata.KeyChain)
	return err
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	sid, err := blobID(filename, userdata.Username)
	if err != nil {
		err = errors.New("sid not found")
		return
	}
	op, err := getBlobOpener(sid, *userdata)
	if err != nil {
		err = errors.New("op not found")
		return
	}
	blob, err := getBlob(sid, op)
	if err != nil {
		return
	}
	file, err := getFileFromBlob(blob)
	if err != nil {
		return nil, err
	}
	var acum []byte
	n := file.Head
	for n != uuid.Nil {
		//opener, ok := file.KeyChain[n]
		opener, errr := getPartCloudKey(n, blob.FileID, file)
		if err != nil {
			err = errr
			return
		}

		var cont []byte
		cont, n, _, err = getContFromNode(n, opener)
		if err != nil {
			err = errors.New("check getContrFromNode")
			return
		}
		acum = append(acum, cont...)
	}

	return acum, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	PK, err := getPubKey(recipientUsername, PUBLICKEY)
	if err != nil {
		return
	}
	uid, err := blobID(filename, userdata.Username)
	if err != nil {
		return
	}
	opener, err := getBlobOpener(uid, *userdata)
	if err != nil {
		return
	}
	blob, err := getBlob(uid, opener)
	if err != nil {
		return
	}

	_, err = getFileFromBlob(blob)
	if err != nil {
		return
	}

	nameShare := genName(filename, recipientUsername)
	shareID, err := uuid.FromBytes(nameShare)
	if err != nil {
		return
	}

	sendOpener := genKey()

	blob.Childs[shareID] = sendOpener
	saveBlob(blob, opener, uid)

	// set the parent now
	blob.ParentBlob = uid
	blob.ParentKey = opener

	blob.Childs = make(map[uuid.UUID][]byte)
	var packet Packet
	packet.BlobObj = blob
	packet.BlobOpener = sendOpener
	packet.ParentOpener = opener

	packetOP := genOpener()
	packetBytes, err := json.Marshal(packet)
	if err != nil {
		return
	}
	encPacket := userlib.SymEnc(packetOP.EncKey, genIV(), packetBytes)
	packetOP.HMAC, err = userlib.HashKDF(packetOP.HMACKey, encPacket)
	if err != nil {
		return
	}

	var ptr PacketPtr
	ptr.PacketID, err = saveBytes(encPacket)
	ptr.PacketOpener = genID()
	if err != nil {
		return
	}
	err = saveOpener(ptr.PacketOpener, packetOP, PK, userdata.Sign)
	if err != nil {
		userlib.DebugMsg("failed here in invite")
		return
	}

	pack, err := json.Marshal(ptr)
	if err != nil {
		return
	}
	packEnc, err := userlib.PKEEnc(PK, pack)
	if err != nil {
		return
	}
	invID, err := blobID(filename, recipientUsername+filename+userdata.Username)
	if err != nil {
		return
	}
	userlib.DatastoreSet(invID, packEnc)
	invitationPtr = invID
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (err error) {
	sid, err := blobID(filename, userdata.Username)
	if err != nil {
		err = errors.New("sid not found")
		return
	}
	enc, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		err = errors.New("cant find in data store the invptr")
		return
	}
	dec, err := userlib.PKEDec(userdata.RSAPriv, enc)
	if err != nil {

		return
	}
	var ptr PacketPtr
	err = json.Unmarshal(dec, &ptr)
	if err != nil {
		return
	}
	DS, err := getPubKey(senderUsername, VERIFYKEY)
	if err != nil {
		return
	}
	OP, err := getOpener(ptr.PacketOpener, userdata.RSAPriv, DS)
	if err != nil {
		userlib.DebugMsg("failed here")
		return
	}
	packetEncBytes, ok := userlib.DatastoreGet(ptr.PacketID)
	if !ok {
		err = errors.New("cant find in data store the packet")
		return
	}
	decPacket, err := verifyAndDecrypt(packetEncBytes, OP)
	if err != nil {
		return
	}
	var packet Packet
	err = json.Unmarshal(decPacket, &packet)
	if err != nil {
		return
	}
	_, ok = userlib.DatastoreGet(sid)
	if ok {
		err = errors.New("file with this name exists")
		return
	}
	err = saveBlob(packet.BlobObj, packet.BlobOpener, sid)
	if err != nil {
		return
	}

	err = saveBlobOpener(sid, packet.BlobOpener, *userdata)
	if err != nil {
		return
	}
	return
}

func modiFiedNodeRekey(file File, fileID uuid.UUID) (reFile File, retID uuid.UUID, err error) {
	reFile.DS, reFile.VS, err = userlib.DSKeyGen()
	if err != nil {
		return
	}
	reFile.PK, reFile.EK, err = userlib.PKEKeyGen()
	if err != nil {
		return
	}
	retID = genID()
	ptr := file.Head
	newHead := genID()
	var curID uuid.UUID
	cur := curID
	curID = newHead
	for ptr != uuid.Nil {
		var fnext uuid.UUID = genID()
		opener, err := getPartCloudKey(ptr, fileID, file)
		if err != nil {
			return reFile, retID, err
		}
		cont, nexptr, contID, err := getContFromNode(ptr, opener)
		if err != nil {
			return reFile, retID, err
		}
		userlib.DatastoreDelete(contID)
		userlib.DatastoreDelete(ptr)
		if nexptr == uuid.Nil {
			fnext = uuid.Nil
		}
		op, err := genNode(cont, fnext, curID)
		if err != nil {
			return reFile, retID, err
		}
		err = savePartCloudKey(curID, retID, op, reFile)
		if err != nil {
			return reFile, retID, err
		}
		cur = curID
		curID = fnext
		ptr = nexptr
	}
	reFile.Head = newHead
	reFile.Tail = cur

	return
}

func reKeyBlob(blob *Blob) (err error) {
	file, err := getFileFromBlob(*blob)
	if err != nil {
		return
	}
	newFile, newID, err := modiFiedNodeRekey(file, blob.FileID)
	if err != nil {
		return
	}
	userlib.DatastoreDelete(blob.FileID)
	blob.FileID = newID
	userlib.DatastoreDelete(blob.FileOpen)
	blob.FileOpen = genID()
	err = saveFileToBlob(newFile, *blob)
	if err != nil {
		return
	}
	return
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) (err error) {
	invID, err := blobID(filename, recipientUsername+filename+userdata.Username)
	if err != nil {
		return
	}
	_, b := userlib.DatastoreGet(invID)
	if b {
		userlib.DatastoreDelete(invID)
	}
	uid, err := blobID(filename, userdata.Username)
	if err != nil {
		return
	}
	opener, err := getBlobOpener(uid, *userdata)
	if err != nil {
		return
	}
	blob, err := getBlob(uid, opener)
	if err != nil {
		return
	}
	_, err = getFileFromBlob(blob)
	if err != nil {
		return
	}
	nameShare := genName(filename, recipientUsername)
	shareID, err := uuid.FromBytes(nameShare)
	if err != nil {
		return
	}
	_, ok := blob.Childs[shareID]
	if !ok {
		err = errors.New("shared blob opener dne")
		return
	}
	delete(blob.Childs, shareID)
	err = reKeyBlob(&blob)
	if err != nil {
		return errors.New("rekey failed")
	}
	saveBlob(blob, opener, uid)
	var m DummyMap
	m.Map = make(map[uuid.UUID]bool)
	syncBlobs(uid, opener, &m, blob)
	return nil
}
func syncChilds(uid uuid.UUID, key []byte, m *DummyMap, target Blob) {
	blob, err := getBlob(uid, key)
	if err != nil {
		return
	}
	_, ok := m.Map[uid]
	if ok {
		return
	}
	m.Map[uid] = true
	for k, v := range blob.Childs {
		syncBlobs(k, v, m, target)
	}

}

type DummyMap struct {
	Map map[uuid.UUID]bool
}

func syncBlobs(uid uuid.UUID, key []byte, m *DummyMap, target Blob) {
	blob, err := getBlob(uid, key)
	if err != nil {
		return
	}
	_, ok := m.Map[uid]
	if ok {
		return
	}
	m.Map[uid] = true
	blob.FileID = target.FileID
	blob.FileOpen = target.FileOpen
	blob.DS = target.DS
	blob.EK = target.EK
	blob.PK = target.PK
	blob.VS = target.VS
	saveBlob(blob, key, uid)
	syncChilds(uid, key, m, target)
	if blob.ParentBlob != uuid.Nil {
		syncBlobs(blob.ParentBlob, blob.ParentKey, m, target)
	}
}
