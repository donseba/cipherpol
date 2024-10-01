package cipherpol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	mathrand "math/rand"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

type (
	Cypher struct {
		characterSet []rune
		grid         [][]rune
		gridSize     int
	}

	Interface interface {
		EncryptWithAutoGridSize(plaintext, password string) error
		Encrypt(plaintext, password string, gridSize int) ([][]rune, error)
		Decrypt(grid [][]rune, password string) (string, error)
		SetCharacterSet(characterSet ...CharacterSet)
		Grid() string
		GridSize() int
		RawGrid() [][]rune
	}

	CharacterSet string
)

const (
	CharacterSetOgham      CharacterSet = "Ogham"
	CharacterSetLinearB    CharacterSet = "Linear B"
	CharacterSetEgyptian   CharacterSet = "Egyptian Hieroglyphs"
	CharacterSetGlagolitic CharacterSet = "Glagolitic Script"
	CharacterSetCoptic     CharacterSet = "Coptic Script"
	CharacterSetGothic     CharacterSet = "Gothic Script"
	CharacterSetPhoenician CharacterSet = "Phoenician Script"
	CharacterSetUgaritic   CharacterSet = "Ugaritic Script"
	CharacterSetViking     CharacterSet = "Viking Runes"
	CharacterSetHiragana   CharacterSet = "Hiragana"
	CharacterSetKatakana   CharacterSet = "Katakana"
	CharacterSetMayan      CharacterSet = "Mayan Numerals"
)

// Character set for the grid
var (
	ErrorNotEnoughPositions     = errors.New("not enough positions to embed data")
	ErrorDataTooLarge           = errors.New("data too large to fit in the grid")
	ErrorInvalidLength          = errors.New("invalid length")
	ErrorSerializedDataTooShort = errors.New("serialized data too short")
	ErrorInvalidRuneInEncoded   = errors.New("invalid rune in encoded string")

	all        []rune
	oGham      []rune
	linearB    []rune
	egyptian   []rune
	glagolitic []rune
	coptic     []rune
	gothic     []rune
	phoenician []rune
	ugaritic   []rune
	viking     []rune
	hiragana   []rune
	katakana   []rune
	mayan      []rune
)

func init() {
	// Ogham characters from U+1680 to U+169F
	for r := rune(0x1680); r <= rune(0x169F); r++ {
		all = append(all, r)
		oGham = append(oGham, r)
	}

	// Linear B Syllabary
	for r := rune(0x10000); r <= rune(0x1007F); r++ {
		all = append(all, r)
		linearB = append(linearB, r)
	}

	// Egyptian Hieroglyphs from U+13000 to U+1342E
	for r := rune(0x13000); r <= rune(0x1342E); r++ {
		all = append(all, r)
		egyptian = append(egyptian, r)
	}

	// Glagolitic Script from U+2C00 to U+2C5F
	for r := rune(0x2C00); r <= rune(0x2C5F); r++ {
		all = append(all, r)
		glagolitic = append(glagolitic, r)
	}

	// Coptic Script from U+03E2 to U+03EF
	for r := rune(0x03E2); r <= rune(0x03EF); r++ {
		all = append(all, r)
		coptic = append(coptic, r)
	}

	// Gothic Script from U+10330 to U+1034A
	for r := rune(0x10330); r <= rune(0x1034A); r++ {
		all = append(all, r)
		gothic = append(gothic, r)
	}

	// Phoenician Script from U+10900 to U+10915
	for r := rune(0x10900); r <= rune(0x10915); r++ {
		all = append(all, r)
		phoenician = append(phoenician, r)
	}

	// Ugaritic Script from U+10380 to U+1039D
	for r := rune(0x10380); r <= rune(0x1039D); r++ {
		all = append(all, r)
		ugaritic = append(ugaritic, r)
	}

	// Viking Runes from U+16A0 to U+16EA
	for r := rune(0x16A0); r <= rune(0x16EA); r++ {
		all = append(all, r)
		viking = append(viking, r)
	}

	// Skip punctuation U+16EB to U+16ED
	// Include runic letters from U+16EE to U+16F0
	for r := rune(0x16EE); r <= rune(0x16F0); r++ {
		all = append(all, r)
		viking = append(viking, r)
	}

	// Hiragana characters from U+3041 to U+3096
	for r := rune(0x3041); r <= rune(0x3096); r++ {
		all = append(all, r)
		hiragana = append(hiragana, r)
	}

	// Katakana characters from U+30A1 to U+30FA
	for r := rune(0x30A1); r <= rune(0x30FA); r++ {
		all = append(all, r)
		katakana = append(katakana, r)
	}

	// Mayan Numerals from U+1D2E0 to U+1D2F3 (optional)
	for r := rune(0x1D2E0); r <= rune(0x1D2F3); r++ {
		all = append(all, r)
		mayan = append(mayan, r)
	}

	// Add more character sets here
}

func NewCypher() *Cypher {
	return &Cypher{
		characterSet: all,
	}
}

func (c *Cypher) SetCharacterSet(characterSet ...CharacterSet) {
	c.characterSet = nil

	for _, cs := range characterSet {
		switch cs {
		case CharacterSetOgham:
			c.characterSet = append(c.characterSet, oGham...)
		case CharacterSetLinearB:
			c.characterSet = append(c.characterSet, linearB...)
		case CharacterSetEgyptian:
			c.characterSet = append(c.characterSet, egyptian...)
		case CharacterSetGlagolitic:
			c.characterSet = append(c.characterSet, glagolitic...)
		case CharacterSetCoptic:
			c.characterSet = append(c.characterSet, coptic...)
		case CharacterSetGothic:
			c.characterSet = append(c.characterSet, gothic...)
		case CharacterSetPhoenician:
			c.characterSet = append(c.characterSet, phoenician...)
		case CharacterSetUgaritic:
			c.characterSet = append(c.characterSet, ugaritic...)
		case CharacterSetViking:
			c.characterSet = append(c.characterSet, viking...)
		case CharacterSetHiragana:
			c.characterSet = append(c.characterSet, hiragana...)
		case CharacterSetKatakana:
			c.characterSet = append(c.characterSet, katakana...)
		case CharacterSetMayan:
			c.characterSet = append(c.characterSet, mayan...)
		}
	}

	if len(c.characterSet) == 0 {
		c.characterSet = all
	}
}

// EncryptWithAutoGridSize encrypts the plaintext message using the provided password
// and automatically adjusts the grid size as needed.
func (c *Cypher) EncryptWithAutoGridSize(plaintext, password string) error {
	// Calculate required grid size
	gridSize, err := c.calculateRequiredGridSize(plaintext)
	if err != nil {
		return err
	}

	// Encrypt the message with the calculated grid size
	err = c.Encrypt(plaintext, password, gridSize)
	if err != nil {
		return err
	}

	c.gridSize = gridSize

	return nil
}

// Encrypt encrypts the plaintext message using the provided password and grid size
func (c *Cypher) Encrypt(plaintext, password string, gridSize int) error {
	// Generate a random salt
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return err
	}

	// Derive a key from the password
	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)

	// Encrypt the plaintext using AES-256-GCM
	ciphertext, nonce, err := c.encryptAESGCM([]byte(plaintext), key)
	if err != nil {
		return err
	}

	// Concatenate salt, nonce, and ciphertext
	serializedData := append(salt, nonce...)
	serializedData = append(serializedData, ciphertext...)

	// Encode serialized data using custom runes
	encodedData := c.encodeToCustomRunes(serializedData, c.characterSet)

	// Include the length prefix
	dataLength := len([]rune(encodedData))
	lengthPrefix := fmt.Sprintf("%05d", dataLength) // 5-digit length
	dataWithLength := lengthPrefix + encodedData

	// Create grid and embed the data
	grid, err := c.embedDataIntoGrid(dataWithLength, password, gridSize)
	if err != nil {
		return err
	}

	c.grid = grid

	return nil
}

func (c *Cypher) Decrypt(grid [][]rune, password string) (string, error) {
	gridSize := len(grid)
	totalCells := gridSize * gridSize

	// Generate positions for length prefix
	positionsForLengthPrefix, err := c.generatePositions(totalCells, 5, password)
	if err != nil {
		return "", err
	}

	// Extract length prefix
	var lengthPrefixRunes []rune
	for _, pos := range positionsForLengthPrefix {
		row := pos / gridSize
		col := pos % gridSize
		r := grid[row][col]
		lengthPrefixRunes = append(lengthPrefixRunes, r)
	}

	lengthPrefix := string(lengthPrefixRunes)
	dataLength, err := strconv.Atoi(lengthPrefix)
	if err != nil {
		return "", err
	}

	// Validate data length
	if dataLength <= 0 || dataLength > totalCells-5 {
		return "", ErrorInvalidLength
	}

	// Generate positions for the rest of the data
	totalDataPositions := 5 + dataLength
	positions, err := c.generatePositions(totalCells, totalDataPositions, password)
	if err != nil {
		return "", err
	}

	dataPositions := positions[5:] // Skip first 5 positions used for length prefix

	var dataRunes []rune
	for _, pos := range dataPositions {
		row := pos / gridSize
		col := pos % gridSize
		r := grid[row][col]
		dataRunes = append(dataRunes, r)
	}

	encodedData := string(dataRunes)

	// Decode data from custom runes
	serializedData, err := c.decodeFromCustomRunes(encodedData, c.characterSet)
	if err != nil {
		return "", err
	}

	// Extract salt, nonce, and ciphertext from serializedData
	if len(serializedData) < 16+12 {
		return "", ErrorSerializedDataTooShort
	}
	salt := serializedData[:16]
	nonce := serializedData[16:28]
	ciphertext := serializedData[28:]

	// Derive the key from the password and salt
	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)

	// Decrypt the ciphertext
	plaintext, err := c.decryptAESGCM(ciphertext, key, nonce)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func (c *Cypher) GridSize() int {
	return c.gridSize
}

func (c *Cypher) RawGrid() [][]rune {
	return c.grid
}

func (c *Cypher) Grid() string {
	var gridStr string
	for _, row := range c.grid {
		for _, cell := range row {
			gridStr += string(cell)
		}
		gridStr += "\n"
	}
	return gridStr
}

func (c *Cypher) encodeToCustomRunes(data []byte, runeSet []rune) string {
	base := big.NewInt(int64(len(runeSet)))
	dataInt := new(big.Int).SetBytes(data)
	var encodedRunes []rune

	for dataInt.Cmp(big.NewInt(0)) > 0 {
		remainder := new(big.Int)
		dataInt.DivMod(dataInt, base, remainder)
		encodedRunes = append(encodedRunes, runeSet[remainder.Int64()])
	}

	// Reverse the slice to get the correct order
	for i, j := 0, len(encodedRunes)-1; i < j; i, j = i+1, j-1 {
		encodedRunes[i], encodedRunes[j] = encodedRunes[j], encodedRunes[i]
	}

	return string(encodedRunes)
}

func (c *Cypher) decodeFromCustomRunes(encodedStr string, runeSet []rune) ([]byte, error) {
	base := big.NewInt(int64(len(runeSet)))
	dataInt := big.NewInt(0)
	runeIndexMap := make(map[rune]int64)
	for idx, r := range runeSet {
		runeIndexMap[r] = int64(idx)
	}

	runes := []rune(encodedStr)
	for _, r := range runes {
		idx, exists := runeIndexMap[r]
		if !exists {
			return nil, fmt.Errorf("%w: %v", ErrorInvalidRuneInEncoded, r)
		}
		dataInt.Mul(dataInt, base)
		dataInt.Add(dataInt, big.NewInt(idx))
	}

	return dataInt.Bytes(), nil
}

// Decrypt decrypts the message from the grid using the provided password
func (c *Cypher) calculateRequiredGridSize(plaintext string) (int, error) {
	// Fixed overhead in characters (length prefix)
	const lengthPrefixSize = 5 // 5 characters for length prefix

	// Calculate the number of bytes to be serialized
	saltSize := 16  // 16 bytes salt
	nonceSize := 12 // 12 bytes nonce (AES-GCM standard)
	plaintextBytes := []byte(plaintext)
	plaintextLength := len(plaintextBytes)
	aesGCMTagSize := 16
	ciphertextSize := plaintextLength + aesGCMTagSize

	// Total bytes to be encoded
	totalBytes := saltSize + nonceSize + ciphertextSize

	// Calculate the encoded data length
	// The encoded length depends on the base (number of runes)
	// Calculate an approximate upper bound
	base := float64(len(c.characterSet))
	// The number of digits required is log_base(totalBytes)
	numDigits := int(math.Ceil((float64(totalBytes*8) / math.Log2(base))))

	totalDataSize := lengthPrefixSize + numDigits

	// Calculate minimum grid size
	totalCellsNeeded := totalDataSize
	gridSize := int(math.Ceil(math.Sqrt(float64(totalCellsNeeded))))

	// Ensure grid size is at least 1
	if gridSize < 1 {
		gridSize = 1
	}

	return gridSize, nil
}

// Helper functions

func (c *Cypher) encryptAESGCM(plaintext, key []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, nil, err
	}

	ciphertext = aesGCM.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func (c *Cypher) decryptAESGCM(ciphertext, key, nonce []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err = aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (c *Cypher) embedDataIntoGrid(data, password string, gridSize int) ([][]rune, error) {
	grid := make([][]rune, gridSize)
	for i := range grid {
		grid[i] = make([]rune, gridSize)
		for j := range grid[i] {
			grid[i][j] = c.randomRune()
		}
	}

	totalCells := gridSize * gridSize
	dataRunes := []rune(data)
	positionCount := len(dataRunes)
	if positionCount > totalCells {
		return nil, ErrorDataTooLarge
	}

	// Generate positions
	positions, err := c.generatePositions(totalCells, positionCount, password)
	if err != nil {
		return nil, err
	}

	// Embed data into grid
	for idx, pos := range positions {
		row := pos / gridSize
		col := pos % gridSize
		grid[row][col] = dataRunes[idx]
	}

	return grid, nil
}

func (c *Cypher) randomRune() rune {
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(c.characterSet))))
	return c.characterSet[idx.Int64()]
}

func (c *Cypher) generatePositions(totalCells, numPositions int, password string) ([]int, error) {
	// Derive a seed from the password
	key := pbkdf2.Key([]byte(password), []byte("position-seed"), 100000, 32, sha256.New)
	h := hmac.New(sha256.New, key)
	h.Write([]byte("seed"))
	seedBytes := h.Sum(nil)
	seed := new(big.Int).SetBytes(seedBytes).Int64()
	if seed < 0 {
		seed = -seed
	}

	// Use math/rand with seed for deterministic pseudorandom sequence
	prng := mathrand.New(mathrand.NewSource(seed))

	// Generate positions
	indices := prng.Perm(totalCells)
	if numPositions > len(indices) {
		return nil, ErrorNotEnoughPositions
	}
	return indices[:numPositions], nil
}
