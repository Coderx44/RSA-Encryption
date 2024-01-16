package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	_ "github.com/lib/pq"
)

const (
	dbUser     = "postgres"
	dbPassword = "postgres"
	dbName     = "encryption"
	dbHost     = "localhost"
	dbPort     = "5432"
)

var db *sql.DB

func initDB() {

	var err error
	db, err = sql.Open("postgres", fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s sslmode=disable",
		dbUser, dbPassword, dbName, dbHost, dbPort))
	if err != nil {
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		panic(err)
	}
}

func closeDB() {
	db.Close()
}

func loadPublicKey(filename string) (pubKey *rsa.PublicKey, err error) {

	publicKeyFile, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading public key file:", err)
		return
	}

	publicKeyBlock, _ := pem.Decode(publicKeyFile)
	if publicKeyBlock == nil || publicKeyBlock.Type != "RSA PUBLIC KEY" {
		fmt.Println("Failed to decode public key")
		return
	}

	pubKey, err = x509.ParsePKCS1PublicKey(publicKeyBlock.Bytes)
	if err != nil {
		fmt.Println("Error parsing public key:", err)
		return
	}

	return pubKey, nil
}

func storeInDatabase(filename string, encryptedData string, encryptedAESKey string) error {

	_, err := db.Exec("INSERT INTO encoded_data (filename, data, key) VALUES ($1, $2, $3)",
		filename, encryptedData, encryptedAESKey)
	if err != nil {
		return err
	}
	return nil
}

func loadPrivateKey(filename string) (privateKey *rsa.PrivateKey, err error) {

	privateKeyFile, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading private key file:", err)
		return
	}

	privateKeyBlock, _ := pem.Decode(privateKeyFile)
	if privateKeyBlock == nil || privateKeyBlock.Type != "RSA PRIVATE KEY" {
		fmt.Println("Failed to decode private key")
		return
	}

	privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		return
	}

	return privateKey, nil
}

func dataToEncrypt(filename string) ([]byte, error) {

	dataToEncrypt, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading data to encrypt:", err)
		return []byte{}, err
	}
	return dataToEncrypt, nil
}

func generateAESKey() ([]byte, error) {

	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		fmt.Println("Error generating random AES key:", err)
		return []byte{}, err
	}

	return aesKey, nil

}

func rsaEncrypt(filename string) error {

	publicKey, err := loadPublicKey("public.pem")
	if err != nil {
		return err

	}

	data, err := dataToEncrypt(filename)
	if err != nil {
		return err
	}

	aesKey, err := generateAESKey()
	if err != nil {
		return err
	}

	encryptedData, err := encryptAES(data, aesKey)
	if err != nil {
		fmt.Println("Error encrypting data with AES:", err)
		return err
	}

	encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, aesKey, nil)
	if err != nil {
		fmt.Println("Error encrypting AES key with RSA:", err)
		return err
	}

	err = storeInDatabase(filename, encryptedData, (base64.StdEncoding.EncodeToString(encryptedAESKey)))
	return err
}

func getData(filename string) (encodedData string, key string, err error) {
	err = db.QueryRow("SELECT data, key FROM encoded_data WHERE filename=$1", filename).
		Scan(&encodedData, &key)
	if err != nil {
		return
	}

	return
}
func rsaDecrypt(filename string) error {

	privateKey, err := loadPrivateKey("priv.pem")
	if err != nil {
		return err
	}

	encodedData, key, err := getData(filename)
	if err != nil {
		return err
	}

	encryptedData, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return err
	}

	encryptedAESKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return err
	}

	decryptedAESKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedAESKey, nil)
	if err != nil {
		fmt.Println("Error decrypting AES key with RSA:", err)
		return err
	}

	decryptedData, err := decryptAES(encryptedData, decryptedAESKey)
	if err != nil {
		fmt.Println("Error decrypting data with AES:", err)
		return err
	}

	fmt.Println("DECRYPTED RSA KEY: \n", string(decryptedData))
	return nil

}

func decryptAES(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	return PKCS7Unpad(ciphertext), nil
}

func PKCS7Unpad(data []byte) []byte {
	length := len(data)
	padding := int(data[length-1])
	return data[:length-padding]
}
func encryptAES(plaintext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plaintext = PKCS7Pad(plaintext, aes.BlockSize)

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func PKCS7Pad(data []byte, blockSize int) []byte {

	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func main() {

	initDB()
	defer closeDB()
	for {
		fmt.Println("1. Encrypt file")
		fmt.Println("2. Decrypt file")
		fmt.Println("3. Exit")

		var choice int
		fmt.Print("Enter your choice: ")
		_, err := fmt.Scan(&choice)
		if err != nil {
			fmt.Println("Error reading choice:", err)
			return
		}

		switch choice {
		case 1:
			var filename string
			fmt.Print("Enter the file name to encrypt: ")
			_, err := fmt.Scan(&filename)
			if err != nil {
				fmt.Println("Error reading file name:", err)
				return
			}
			err = rsaEncrypt(filename)
			if err != nil {
				fmt.Println(err)
			} else {
				fmt.Println("encryption completed successfully.")
			}
		case 2:
			var filename string
			fmt.Print("Enter the file name to decrypt: ")
			_, err := fmt.Scan(&filename)
			if err != nil {
				fmt.Println("Error reading file name:", err)
				return
			}
			err = rsaDecrypt(filename)
			if err != nil {
				fmt.Println(err)
			}
		case 3:
			fmt.Println("Exiting...")
			os.Exit(0)
		default:
			fmt.Println("Invalid choice. Please enter a valid option.")
		}
	}

}
