package cipherpol

import (
	"fmt"
	"testing"
)

func TestDecrypt(t *testing.T) {
	plaintext := `Well, the way they make shows is, they make one show. That show's called a pilot. Then they show that show to the people who make shows, and on the strength of that one show they decide if they're going to make more shows. Some pilots get picked and become television programs. Some don't, become nothing. She starred in one of the ones that became nothing.

You think water moves fast? You should see ice. It moves like it has a mind. Like it knows it killed the world once and got a taste for murder. After the avalanche, it took us a week to climb out. Now, I don't know exactly when we turned on each other, but I know that seven of us survived the slide... and only five made it out. Now we took an oath, that I'm breaking now. We said we'd say it was the snow that killed the other two, but it wasn't. Nature is lethal but it doesn't hold a candle to man.
`
	password := "SuperSecretPassword"

	cp := NewCypher()
	cp.SetCharacterSet(CharacterSetPhoenician)

	// Encrypt the message
	err := cp.EncryptWithAutoGridSize(plaintext, password)
	if err != nil {
		t.Log("Encryption error:", err)
		return
	}

	// Display the grid
	fmt.Println("Encrypted Grid:")
	fmt.Println(cp.Grid())

	// Decrypt the message
	decrypted, err := cp.Decrypt(cp.RawGrid(), password)
	if err != nil {
		t.Log("Decryption error:", err)
		return
	}

	if decrypted != plaintext {
		t.Error("Decrypted message does not match the original plaintext.")
	}
}
