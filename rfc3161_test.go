package rfc3161

import (
	"crypto"
	"crypto/sha1"
	"errors"
	"fmt"
	"github.com/blang/semver"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestUnmarshal(t *testing.T) {
	req, err := ReadTSQ("./test/sha1.tsq")
	if err != nil {
		t.Error(err)
	}
	err = req.Verify()
	if err != nil {
		t.Error(err)
	}
	resp, err := ReadTSR("./test/sha1.response.tsr")
	if err != nil {
		t.Error(err)
	}
	err = resp.Verify(req)
	if err != nil {
		t.Error(err)
	}

	req, err = ReadTSQ("./test/sha1_nonce.tsq")
	if err != nil {
		t.Error(err)
	}
	err = req.Verify()
	if err != nil {
		t.Error(err)
	}
	resp, err = ReadTSR("./test/sha1_nonce.response.tsr")
	if err != nil {
		t.Error(err)
	}
	err = resp.Verify(req)
	if err != nil {
		t.Error(err)
	}

}

// Contruct the tsr manually
func TestReqBuildManually(t *testing.T) {
	mes, err := ioutil.ReadFile("./test/message.txt")
	if err != nil {
		t.Error(err)
	}
	digest := sha1.Sum(mes)

	tsr2, err := NewTimeStampReq(crypto.SHA1, digest[:])
	if err != nil {
		t.Error(err)
	}
	err = tsr2.GenerateNonce()
	if err != nil {
		t.Error(err)
	}
	err = tsr2.Verify()
	if err != nil {
		t.Error(err)
	}
}

// Round-trip test with OpenSSL
func TestOpenSSL(t *testing.T) {
	err := checkOpenSSL()
	if err != nil {
		fmt.Println("Unable to test OpenSSL. Skipping OpenSSL Test. " + err.Error())
		return
	}

	// Create temp dir
	dir, err := ioutil.TempDir("", "rfc3161_test")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dir) // clean up

	// Files
	keypath := "private.pem"
	csrpath := "request.csr"
	crtpath := "cert.pem"
	tsqpath := "request.tsq"
	tsrpath := "response.tsr"
	cnfpath := "openssl.conf"
	mespath := "message.txt"

	// Copy config and message
	os.Link("test/openssl.conf", dir+"/"+cnfpath)
	os.Link("test/message.txt", dir+"/"+mespath)

	// Change directory to our temporary working directory
	curdir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(curdir)

	// Commands
	commands := [][]string{
		{"genrsa", "-out", keypath, "1024"},
		{"req", "-new", "-key", keypath, "-out", csrpath, "-subj", "/C=GB/ST=London/L=London/O=GORFC3161/OU=Testing/CN=example.com", "-config", cnfpath},
		{"x509", "-req", "-days", "365", "-in", csrpath, "-signkey", keypath, "-out", crtpath, "-extfile", cnfpath},
		{"ts", "-query", "-data", mespath, "-sha1", "-out", tsqpath},
		{"ts", "-reply", "-queryfile", tsqpath, "-out", tsrpath, "-inkey", keypath, "-signer", crtpath, "-config", cnfpath},
	}

	// Run commands
	for _, cmd := range commands {
		out, err := exec.Command("openssl", cmd...).Output()
		if err != nil {
			t.Error(err, string(out), string(err.(*exec.ExitError).Stderr))
		}
	}

	req, err := ReadTSQ(tsqpath)
	if err != nil {
		t.Error(err)
	}
	resp, err := ReadTSR(tsrpath)
	if err != nil {
		t.Error(err)
	}
	err = resp.Verify(req)
	if err != nil {
		t.Error(err)
	}
}

func checkOpenSSL() error {
	out, err := exec.Command("openssl", "version").Output()
	if err != nil {
		return err
	}
	ver := strings.TrimRight(strings.Split(string(out), " ")[1], "abcdefghijklmnopqrstuvwxyz")
	version, err := semver.Make(ver)
	if err != nil {
		return err
	}
	requiredVersion, _ := semver.Make("1.0.0")

	if version.LT(requiredVersion) {
		return errors.New("OpenSSL is required to be at least version 1.0.0 to test Time Stamping")
	}

	return nil
}
