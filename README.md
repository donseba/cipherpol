# CipherPol
CipherPol is a Go package that implements a grid-based cipher utilizing various ancient and unique character sets (runes) for data encryption and decryption. It allows you to encrypt plaintext messages into a grid of custom runes and decrypt them back using a password. The grid size adjusts automatically based on the length of the message, and you can select from multiple character sets to create visually diverse and intriguing encrypted grids.

## Features

- **Grid-Based Encryption**: Encrypt messages into a grid of runes, creating a unique visual representation.
- **Customizable Character Sets**: Choose from various ancient scripts and runes for the grid characters.
- **Automatic Grid Size Adjustment**: The grid size adjusts automatically based on the length of the plaintext.
- **Secure Encryption**: Utilizes AES-256-GCM encryption with PBKDF2 key derivation for strong security.
- **Deterministic Decryption**: The same password and character set are required to decrypt the message successfully.
- **Error Handling**: Provides meaningful errors for invalid inputs and decryption failures.

## Installation

To use CipherPol in your Go project, you can install it using `go get`:

```bash
go get github.com/donseba/cipherpol
```

## Usage

Here's a simple example of how to encrypt and decrypt a message using CipherPol:

```go
package main

import (
    "fmt"
    "github.com/donseba/cipherpol"
)

func main() {
    // Create a new CipherPol instance with a password and character set
    cp := cipherpol.NewCypher()

	cp.SetCharacterSet(cipherpol.CharacterSetPhoenician)

	password := "SuperSecretPassword"
	
	// Encrypt the message
	err := cp.EncryptWithAutoGridSize("Hello, CipherPol!", password)
	if err != nil {
        fmt.Println("Encryption error:", err)
        return
    }

	// Display the grid
	fmt.Println("Encrypted Grid:")
	fmt.Println(cp.Grid())
	
    fmt.Println("Encrypted message:", cp.Grid())

    // Decrypt the message
    decrypted, err := cp.Decrypt(cp.RawGrid(), password)
    if err != nil {
        fmt.Println("Decryption error:", err)
        return
    }

    fmt.Println("Decrypted message:", decrypted)
}
```
the encoded grid/message would look like: 

```bash
𐤉𐤆𐤁𐤈𐤂𐤇𐤌𐤉𐤂𐤂𐤓
𐤁𐤅𐤎𐤆𐤐𐤅𐤍𐤍𐤓𐤈𐤓
𐤇𐤈𐤕𐤃𐤂𐤃𐤊𐤃𐤐𐤓𐤂
𐤎𐤊𐤕𐤐𐤋𐤌𐤁𐤓𐤒𐤔𐤂
𐤐𐤋𐤓𐤊𐤐𐤂𐤀𐤀𐤁𐤔𐤍
𐤌𐤈𐤎𐤋𐤆0𐤀𐤓𐤍𐤏𐤐
𐤅𐤇𐤋𐤀𐤃𐤎𐤂0𐤈𐤏𐤒
𐤍0𐤇𐤃𐤏𐤀𐤏𐤒𐤍𐤉𐤊
𐤇𐤁𐤀𐤂𐤐𐤅𐤁𐤈𐤏1𐤄
𐤋𐤑𐤐1𐤊𐤔𐤕𐤔𐤎𐤂𐤀
𐤇𐤁𐤓𐤁𐤎𐤊𐤎𐤐𐤉𐤆𐤇
```


## Character Sets

CipherPol supports a variety of ancient and unique character sets:

- **Ogham** (`CharacterSetOgham`): Early Medieval Irish script.
- **Linear B** (`CharacterSetLinearB`): Ancient Mycenaean Greek script.
- **Egyptian Hieroglyphs** (`CharacterSetEgyptian`): Ancient Egyptian writing system.
- **Glagolitic Script** (`CharacterSetGlagolitic`): Oldest known Slavic alphabet.
- **Coptic Script** (`CharacterSetCoptic`): Used for the Coptic language.
- **Gothic Script** (`CharacterSetGothic`): Used for writing the Gothic language.
- **Phoenician Script** (`CharacterSetPhoenician`): Ancient Semitic script.
- **Ugaritic Script** (`CharacterSetUgaritic`): Used in ancient Ugarit.
- **Viking Runes** (`CharacterSetViking`): Runic alphabets used by Germanic peoples.
- **Hiragana** (`CharacterSetHiragana`): Japanese syllabary.
- **Katakana** (`CharacterSetKatakana`): Japanese syllabary.
- **Mayan Numerals** (`CharacterSetMayan`): Ancient Mayan number system.

If no character set is specified, all available character sets are used by default.

## Selecting Character Sets

You can select a character set for the grid using the `SetCharacterSet` method:

```go
// Set custom character sets
cipher.SetCharacterSet(
    cipherpol.CharacterSetViking,
    cipherpol.CharacterSetHiragana,
    cipherpol.CharacterSetEgyptian,
)
```

if you don't specify any character set, all available character sets will be used by default.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
