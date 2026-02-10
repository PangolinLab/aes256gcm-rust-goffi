//go:build cgo
// +build cgo

package aes_256_gcm_ffi

/*
	#cgo CFLAGS: -I${SRCDIR}/include
	#cgo LDFLAGS: -lkernel32 -lntdll -luserenv -lws2_32 -ldbghelp -L${SRCDIR}/bin -laes_256_gcm
	#include <stdlib.h>
	#include <aes_256_gcm_interface.h>
*/
import "C"
import (
	"encoding/hex"
	"errors"
	"filepath"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"unsafe"
)

// definite the var
const (
	AES256KeyLength = 32
	GCMNonceLength  = 12
)

// precompile regex
var (
	hexRegex = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

func init() {
    // 动态库最终路径
    var libFile string
    switch runtime.GOOS {
    case "windows":
        libFile = "bin/aes_256_gcm.dll"
    case "darwin":
        libFile = "bin/libaes_256_gcm.dylib"
    default:
        libFile = "bin/libaes_256_gcm.so"
    }

    // 如果库不存在，则编译 Rust 并复制到 bin/
    if _, err := os.Stat(libFile); os.IsNotExist(err) {
        // Rust 源码目录（Cargo.toml 所在目录）
        rustDir := "../" // 根据你的目录结构调整
        buildCmd := exec.Command("cargo", "build", "--release")
        buildCmd.Dir = rustDir
        buildCmd.Stdout = os.Stdout
        buildCmd.Stderr = os.Stderr
        if err := buildCmd.Run(); err != nil {
            panic("Failed to build Rust library: " + err.Error())
        }

        // 源文件路径（默认 target/release/）
        var srcLib string
        switch runtime.GOOS {
        case "windows":
            srcLib = filepath.Join(rustDir, "target", "release", "aes_256_gcm.dll")
        case "darwin":
            srcLib = filepath.Join(rustDir, "target", "release", "libaes_256_gcm.dylib")
        default:
            srcLib = filepath.Join(rustDir, "target", "release", "libaes_256_gcm.so")
        }

        // 确保 bin 目录存在
        _ = os.MkdirAll("bin", 0755)

        // 复制库到 bin/
        input, err := os.ReadFile(srcLib)
        if err != nil {
            panic("Failed to read Rust library: " + err.Error())
        }
        if err := os.WriteFile(libFile, input, 0644); err != nil {
            panic("Failed to write library to bin/: " + err.Error())
        }
    }
}

// isValidHex checks if a string is a valid hexadecimal string
func isValidHex(s string) (bool, error) {
	if s == "" {
		return false, errors.New("empty string")
	}
	if len(s)%2 != 0 {
		return false, nil
	}
	matched := hexRegex.MatchString(s)
	if !matched {
		return false, nil
	}
	_, err := hex.DecodeString(s)
	return err == nil, nil
}

// createCString creates a C string and ensures memory is freed even on panic.
func createCString(s string) (*C.char, func()) {
	cStr := C.CString(s)
	return cStr, func() { C.free(unsafe.Pointer(cStr)) }
}

// Encrypt encrypts plaintext using AES-256-GCM
func Encrypt(key, nonce, plaintext []byte) ([]byte, error) {
	keyLen := len(key)
	if keyLen != AES256KeyLength {
		return nil, errors.New(fmt.Sprintf("invalid aes-256-gcm key length: expected %d bytes, got %d", AES256KeyLength, keyLen))
	}
	nonceLen := len(nonce)
	if nonceLen != GCMNonceLength {
		return nil, errors.New(fmt.Sprintf("invalid aes-256-gcm nonce length: expected %d bytes, got %d", GCMNonceLength, nonceLen))
	}
	if plaintext == nil {
		return nil, errors.New("invalid aes-256-gcm plaintext: cannot be nil")
	}

	// to hex
	keyHexStr := hex.EncodeToString(key)
	nonceHexStr := hex.EncodeToString(nonce)
	ptHexStr := hex.EncodeToString(plaintext)

	// C string
	keyHex, freeKey := createCString(keyHexStr)
	nonceHex, freeNonce := createCString(nonceHexStr)
	ptHex, freePt := createCString(ptHexStr)
	defer freeKey()
	defer freeNonce()
	defer freePt()

	// call Rust
	res := C.aes_256_gcm_encrypt(keyHex, nonceHex, ptHex)
	if res == nil {
		return nil, errors.New("aes-256-gcm encryption failed")
	}
	defer C.aes_256_gcm_free(res)

	// prase res
	outHex := C.GoString(res)
	ct, err := hex.DecodeString(outHex)
	if err != nil {
		return nil, err
	}

	// return nonce||ct
	final := append(nonce, ct...)
	return final, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM
func Decrypt(key, combined []byte) ([]byte, error) {
	keyLen := len(key)
	if keyLen != AES256KeyLength {
		return nil, errors.New(fmt.Sprintf("invalid aes-256-gcm key length: expected %d bytes, got %d", AES256KeyLength, keyLen))
	}
	combinedLen := len(combined)
	if combinedLen <= GCMNonceLength {
		return nil, errors.New(fmt.Sprintf("invalid aes-256-gcm nonce and ciphertext length: expected more than %d bytes, got %d", GCMNonceLength, combinedLen))
	}

	// depart nonce 和 ct
	nonce := combined[:GCMNonceLength]
	ciphertext := combined[GCMNonceLength:]

	// to hex
	keyHexStr := hex.EncodeToString(key)
	nonceHexStr := hex.EncodeToString(nonce)
	ctHexStr := hex.EncodeToString(ciphertext)

	keyHex, freeKey := createCString(keyHexStr)
	nonceHex, freeNonce := createCString(nonceHexStr)
	ctHex, freeCt := createCString(ctHexStr)
	defer freeKey()
	defer freeNonce()
	defer freeCt()

	// call Rust
	res := C.aes_256_gcm_decrypt(keyHex, nonceHex, ctHex)
	if res == nil {
		return nil, errors.New("aes-256-gcm decryption failed")
	}
	defer C.aes_256_gcm_free(res)

	outHex := C.GoString(res)
	ok, err := isValidHex(outHex)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("invalid hex output from aes-256-gcm decryption")
	}
	return hex.DecodeString(outHex)
}
