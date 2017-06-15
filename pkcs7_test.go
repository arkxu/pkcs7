package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestVerify(t *testing.T) {
	fixture := UnmarshalTestFixture(SignedTestFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}

	if err := p7.Verify(); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}
	expected := []byte("We the People")
	if bytes.Compare(p7.Content, expected) != 0 {
		t.Errorf("Signed content does not match.\n\tExpected:%s\n\tActual:%s", expected, p7.Content)
	}
}

func TestDecrypt(t *testing.T) {
	fixture := UnmarshalTestFixture(EncryptedTestFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Fatal(err)
	}
	content, err := p7.Decrypt(fixture.Certificate, fixture.PrivateKey)
	if err != nil {
		t.Errorf("Cannot Decrypt with error: %v", err)
	}
	expected := []byte("This is a test")
	if bytes.Compare(content, expected) != 0 {
		t.Errorf("Decrypted result does not match.\n\tExpected:%s\n\tActual:%s", expected, content)
	}
}

func TestDegenerateCertificate(t *testing.T) {
	cert, err := createTestCertificate()
	if err != nil {
		t.Fatal(err)
	}
	deg, err := DegenerateCertificate(cert.Certificate.Raw)
	if err != nil {
		t.Fatal(err)
	}
	testOpenSSLParse(t, deg)
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: deg})
}

// writes the cert to a temporary file and tests that openssl can read it.
func testOpenSSLParse(t *testing.T, certBytes []byte) {
	tmpCertFile, err := ioutil.TempFile("", "testCertificate")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpCertFile.Name()) // clean up

	if _, err := tmpCertFile.Write(certBytes); err != nil {
		t.Fatal(err)
	}

	opensslCMD := exec.Command("openssl", "pkcs7", "-inform", "der", "-in", tmpCertFile.Name())
	_, err = opensslCMD.Output()
	if err != nil {
		t.Fatal(err)
	}

	if err := tmpCertFile.Close(); err != nil {
		t.Fatal(err)
	}

}

func TestSign(t *testing.T) {
	cert, err := createTestCertificate()
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("Hello World")
	for _, testDetach := range []bool{false, true} {
		toBeSigned, err := NewSignedData(content)
		if err != nil {
			t.Fatalf("Cannot initialize signed data: %s", err)
		}
		if err := toBeSigned.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{}); err != nil {
			t.Fatalf("Cannot add signer: %s", err)
		}
		if testDetach {
			t.Log("Testing detached signature")
			toBeSigned.Detach()
		} else {
			t.Log("Testing attached signature")
		}
		signed, err := toBeSigned.Finish()
		if err != nil {
			t.Fatalf("Cannot finish signing data: %s", err)
		}
		pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})
		p7, err := Parse(signed)
		if err != nil {
			t.Fatalf("Cannot parse our signed data: %s", err)
		}
		if testDetach {
			p7.Content = content
		}
		if bytes.Compare(content, p7.Content) != 0 {
			t.Errorf("Our content was not in the parsed data:\n\tExpected: %s\n\tActual: %s", content, p7.Content)
		}
		if err := p7.Verify(); err != nil {
			t.Errorf("Cannot verify our signed data: %s", err)
		}
	}
}

func TestSignNoAttribute(t *testing.T) {
	cert, err := createTestCertificate()
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("Hello World")
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}
	if err := toBeSigned.AddNoAttributeSigner(cert.Certificate, cert.PrivateKey); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})
	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("Cannot parse our signed data: %s", err)
	}
	if bytes.Compare(content, p7.Content) != 0 {
		t.Errorf("Our content was not in the parsed data:\n\tExpected: %s\n\tActual: %s", content, p7.Content)
	}
	if err := p7.Verify(); err != nil {
		t.Errorf("Cannot verify our signed data: %s", err)
	}
}

func ExampleSignedData() {
	// generate a signing cert or load a key pair
	cert, err := createTestCertificate()
	if err != nil {
		fmt.Printf("Cannot create test certificates: %s", err)
	}

	// Initialize a SignedData struct with content to be signed
	signedData, err := NewSignedData([]byte("Example data to be signed"))
	if err != nil {
		fmt.Printf("Cannot initialize signed data: %s", err)
	}

	// Add the signing cert and private key
	if err := signedData.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{}); err != nil {
		fmt.Printf("Cannot add signer: %s", err)
	}

	// Call Detach() is you want to remove content from the signature
	// and generate an S/MIME detached signature
	signedData.Detach()

	// Finish() to obtain the signature bytes
	detachedSignature, err := signedData.Finish()
	if err != nil {
		fmt.Printf("Cannot finish signing data: %s", err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: detachedSignature})
}

func TestOpenSSLVerifyDetachedSignature(t *testing.T) {
	rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil)
	if err != nil {
		t.Fatalf("Cannot generate root cert: %s", err)
	}
	signerCert, err := createTestCertificateByIssuer("PKCS7 Test Signer Cert", rootCert)
	if err != nil {
		t.Fatalf("Cannot generate signer cert: %s", err)
	}
	content := []byte("Hello World")
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}
	if err := toBeSigned.AddSigner(signerCert.Certificate, signerCert.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	toBeSigned.Detach()
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}

	// write the root cert to a temp file
	tmpRootCertFile, err := ioutil.TempFile("", "pkcs7TestRootCA")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpRootCertFile.Name()) // clean up
	fd, err := os.OpenFile(tmpRootCertFile.Name(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		t.Fatal(err)
	}
	pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Certificate.Raw})
	fd.Close()

	// write the signature to a temp file
	tmpSignatureFile, err := ioutil.TempFile("", "pkcs7Signature")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpSignatureFile.Name()) // clean up
	ioutil.WriteFile(tmpSignatureFile.Name(), signed, 0755)

	// write the content to a temp file
	tmpContentFile, err := ioutil.TempFile("", "pkcs7Content")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpContentFile.Name()) // clean up
	ioutil.WriteFile(tmpContentFile.Name(), content, 0755)

	// call openssl to verify the signature on the content using the root
	opensslCMD := exec.Command("openssl", "smime", "-verify",
		"-in", tmpSignatureFile.Name(), "-inform", "DER",
		"-content", tmpContentFile.Name(),
		"-CAfile", tmpRootCertFile.Name())
	out, err := opensslCMD.Output()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("openssl command failed with %s", err)
	}
}

func TestEncrypt(t *testing.T) {
	modes := []int{
		EncryptionAlgorithmDESCBC,
		EncryptionAlgorithmAES128GCM,
	}

	for _, mode := range modes {
		ContentEncryptionAlgorithm = mode

		plaintext := []byte("Hello Secret World!")
		cert, err := createTestCertificate()
		if err != nil {
			t.Fatal(err)
		}
		encrypted, err := Encrypt(plaintext, []*x509.Certificate{cert.Certificate})
		if err != nil {
			t.Fatal(err)
		}
		p7, err := Parse(encrypted)
		if err != nil {
			t.Fatalf("cannot Parse encrypted result: %s", err)
		}
		result, err := p7.Decrypt(cert.Certificate, cert.PrivateKey)
		if err != nil {
			t.Fatalf("cannot Decrypt encrypted result: %s", err)
		}
		if bytes.Compare(plaintext, result) != 0 {
			t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
		}
	}
}

func TestUnmarshalSignedAttribute(t *testing.T) {
	cert, err := createTestCertificate()
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("Hello World")
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}
	oidTest := asn1.ObjectIdentifier{2, 3, 4, 5, 6, 7}
	testValue := "TestValue"
	if err := toBeSigned.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{
		ExtraSignedAttributes: []Attribute{Attribute{Type: oidTest, Value: testValue}},
	}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}
	p7, err := Parse(signed)
	var actual string
	err = p7.UnmarshalSignedAttribute(oidTest, &actual)
	if err != nil {
		t.Fatalf("Cannot unmarshal test value: %s", err)
	}
	if testValue != actual {
		t.Errorf("Attribute does not match test value\n\tExpected: %s\n\tActual: %s", testValue, actual)
	}
}

func TestPad(t *testing.T) {
	tests := []struct {
		Original  []byte
		Expected  []byte
		BlockSize int
	}{
		{[]byte{0x1, 0x2, 0x3, 0x10}, []byte{0x1, 0x2, 0x3, 0x10, 0x4, 0x4, 0x4, 0x4}, 8},
		{[]byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0}, []byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8}, 8},
	}
	for _, test := range tests {
		padded, err := pad(test.Original, test.BlockSize)
		if err != nil {
			t.Errorf("pad encountered error: %s", err)
			continue
		}
		if bytes.Compare(test.Expected, padded) != 0 {
			t.Errorf("pad results mismatch:\n\tExpected: %X\n\tActual: %X", test.Expected, padded)
		}
	}
}

type certKeyPair struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

func createTestCertificate() (certKeyPair, error) {
	signer, err := createTestCertificateByIssuer("Eddard Stark", nil)
	if err != nil {
		return certKeyPair{}, err
	}
	fmt.Println("Created root cert")
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: signer.Certificate.Raw})
	pair, err := createTestCertificateByIssuer("Jon Snow", signer)
	if err != nil {
		return certKeyPair{}, err
	}
	fmt.Println("Created signer cert")
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate.Raw})
	return *pair, nil
}

func createTestCertificateByIssuer(name string, issuer *certKeyPair) (*certKeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 32)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber:       serialNumber,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"Acme Co"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	var issuerCert *x509.Certificate
	var issuerKey crypto.PrivateKey
	if issuer != nil {
		issuerCert = issuer.Certificate
		issuerKey = issuer.PrivateKey
	} else {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		issuerCert = &template
		issuerKey = priv
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.Public(), issuerKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}
	return &certKeyPair{
		Certificate: leaf,
		PrivateKey:  priv,
	}, nil
}

type TestFixture struct {
	Input       []byte
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

func UnmarshalTestFixture(testPEMBlock string) TestFixture {
	var result TestFixture
	var derBlock *pem.Block
	var pemBlock = []byte(testPEMBlock)
	for {
		derBlock, pemBlock = pem.Decode(pemBlock)
		if derBlock == nil {
			break
		}
		switch derBlock.Type {
		case "PKCS7":
			result.Input = derBlock.Bytes
		case "CERTIFICATE":
			result.Certificate, _ = x509.ParseCertificate(derBlock.Bytes)
		case "PRIVATE KEY":
			result.PrivateKey, _ = x509.ParsePKCS1PrivateKey(derBlock.Bytes)
		}
	}

	return result
}

func MarshalTestFixture(t TestFixture, w io.Writer) {
	if t.Input != nil {
		pem.Encode(w, &pem.Block{Type: "PKCS7", Bytes: t.Input})
	}
	if t.Certificate != nil {
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: t.Certificate.Raw})
	}
	if t.PrivateKey != nil {
		pem.Encode(w, &pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(t.PrivateKey)})
	}
}

var SignedTestFixture = `
-----BEGIN PKCS7-----
MIIDgwYJKoZIhvcNAQcCoIIDdDCCA3ACAQExDTALBglghkgBZQMEAgEwHAYJKoZI
hvcNAQcBoA8EDVdlIHRoZSBQZW9wbGWgggHyMIIB7jCCAVegAwIBAgIEHHL55DAN
BgkqhkiG9w0BAQsFADApMRAwDgYDVQQKEwdBY21lIENvMRUwEwYDVQQDEwxFZGRh
cmQgU3RhcmswHhcNMTcwNjE1MjMyNTE1WhcNMTgwNjE1MjMyNTE1WjAlMRAwDgYD
VQQKEwdBY21lIENvMREwDwYDVQQDEwhKb24gU25vdzCBnzANBgkqhkiG9w0BAQEF
AAOBjQAwgYkCgYEAqjvmYpw92Ai0kUT7MD60gwrsPTmg7l4yLYKUYGT++2/CZz35
EjFQw1X1UhFz2oUhVHSg2RE++/Y8WaBbOvrwOi0yCBQUAq9O0+HQ3crbGQErlx3G
ur7+YT7baREMp25Wef0lTlcwP8V0dK9LMqUQCVv7rmKjsZmJTL6/RDXawfsCAwEA
AaMnMCUwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMEMA0GCSqG
SIb3DQEBCwUAA4GBAKRDojWghuR5HBA3WjiIEcgsSnKG+A2v3ssO+6FPQh0byOvs
z+TDHtSYRVhuA5v0VbQ9zn8Ci5gDZwe3C/Z4VefEudvfxS/sBI2JfYgikm3mmdjg
uebzAIQpKux4vg+wBHoWGOs91o1d40mFOGuhrQYAAUGNeGvSD+Vn2OoZyav5MYIB
RjCCAUICAQEwMTApMRAwDgYDVQQKEwdBY21lIENvMRUwEwYDVQQDEwxFZGRhcmQg
U3RhcmsCBBxy+eQwCwYJYIZIAWUDBAIBoG0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
DQEHATAgBgkqhkiG9w0BCQUxExcRMTcwNjE1MTYyNTE1LTA3MDAwLwYJKoZIhvcN
AQkEMSIEIBQYUp7yGOCviPH0BZ0jLTQx+zZj3ff1zOuribMY8vHFMAsGCSqGSIb3
DQEBAQSBgGu5gzfx6AdAU/9lPXFE48DqDp/y+UOLQ8oiWcwQeyy7h8MmwZwbLdO6
qRpoooPHzfWbbfyr9amjgfjS7GYOgEvYlSBVqOe54oC7DU/LpCG/obrsGV3fdI8p
CyFRxT6GaQNaSpMMNMPyEgjyJxjOhWUExWYQ8w6lYkaqSWwGhVhK
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIB1TCCAUCgAwIBAgIEabg3LTALBgkqhkiG9w0BAQswKTEQMA4GA1UEChMHQWNt
ZSBDbzEVMBMGA1UEAxMMRWRkYXJkIFN0YXJrMB4XDTE1MDUwNjA0MjQ0OFoXDTE2
MDUwNjA0MjQ0OFowJTEQMA4GA1UEChMHQWNtZSBDbzERMA8GA1UEAxMISm9uIFNu
b3cwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKq/rUxeJmT+azMJV6dcvnK0
bRabi1xdc7wWYmDHyLwB8KNbWvBNSHMhDydYyIijHMG83qOpAJmcyCUQk3s6vY8F
1LCm0E73Hzh/R5o1JlwUVhV2WKELPzmmhWuOXXh5sBHjEJLklhLWIlSimV7STrX5
SiE9zK8iRA4oiLTJHcm1AgMBAAGjEjAQMA4GA1UdDwEB/wQEAwIAoDALBgkqhkiG
9w0BAQsDgYEAytRMHmVkS/n+2fidJFc2PM16bXAWleC3+cBmSSyVVIKd926SzaU9
8mnUvvl0CfnL7Vt8AA0MwUkzHbsjhfGX/i+04460Nvhdh2zWylIQUCrncU37/XSR
3Smw/p4AgnUCWJCMtmHsbKDRtAvJ0JIIMmsWXfyevcQ1ceqbot0o/LA=
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIICXgIBAAKBgQCqv61MXiZk/mszCVenXL5ytG0Wm4tcXXO8FmJgx8i8AfCjW1rw
TUhzIQ8nWMiIoxzBvN6jqQCZnMglEJN7Or2PBdSwptBO9x84f0eaNSZcFFYVdlih
Cz85poVrjl14ebAR4xCS5JYS1iJUople0k61+UohPcyvIkQOKIi0yR3JtQIDAQAB
AoGBAIPLCR9N+IKxodq11lNXEaUFwMHXc1zqwP8no+2hpz3+nVfplqqubEJ4/PJY
5AgbJoIfnxVhyBXJXu7E+aD/OPneKZrgp58YvHKgGvvPyJg2gpC/1Fh0vQB0HNpI
1ZzIZUl8ZTUtVgtnCBUOh5JGI4bFokAqrT//Uvcfd+idgxqBAkEA1ZbP/Kseld14
qbWmgmU5GCVxsZRxgR1j4lG3UVjH36KXMtRTm1atAam1uw3OEGa6Y3ANjpU52FaB
Hep5rkk4FQJBAMynMo1L1uiN5GP+KYLEF5kKRxK+FLjXR0ywnMh+gpGcZDcOae+J
+t1gLoWBIESH/Xt639T7smuSfrZSA9V0EyECQA8cvZiWDvLxmaEAXkipmtGPjKzQ
4PsOtkuEFqFl07aKDYKmLUg3aMROWrJidqsIabWxbvQgsNgSvs38EiH3wkUCQQCg
ndxb7piVXb9RBwm3OoU2tE1BlXMX+sVXmAkEhd2dwDsaxrI3sHf1xGXem5AimQRF
JBOFyaCnMotGNioSHY5hAkEAxyXcNixQ2RpLXJTQZtwnbk0XDcbgB+fBgXnv/4f3
BCvcu85DqJeJyQv44Oe1qsXEX9BfcQIOVaoep35RPlKi9g==
-----END PRIVATE KEY-----`

// Content is "This is a test"
var EncryptedTestFixture = `
-----BEGIN PKCS7-----
MIIBFwYJKoZIhvcNAQcDoIIBCDCCAQQCAQAxgcowgccCAQAwMjApMRAwDgYDVQQK
EwdBY21lIENvMRUwEwYDVQQDEwxFZGRhcmQgU3RhcmsCBQDL+CvWMAsGCSqGSIb3
DQEBAQSBgKyP/5WlRTZD3dWMrLOX6QRNDrXEkQjhmToRwFZdY3LgUh25ZU0S/q4G
dHPV21Fv9lQD+q7l3vfeHw8M6Z1PKi9sHMVfxAkQpvaI96DTIT3YHtuLC1w3geCO
8eFWTq2qS4WChSuS/yhYosjA1kTkE0eLnVZcGw0z/WVuEZznkdyIMDIGCSqGSIb3
DQEHATARBgUrDgMCBwQImpKsUyMPpQigEgQQRcWWrCRXqpD5Njs0GkJl+g==
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIB1jCCAUGgAwIBAgIFAMv4K9YwCwYJKoZIhvcNAQELMCkxEDAOBgNVBAoTB0Fj
bWUgQ28xFTATBgNVBAMTDEVkZGFyZCBTdGFyazAeFw0xNTA1MDYwMzU2NDBaFw0x
NjA1MDYwMzU2NDBaMCUxEDAOBgNVBAoTB0FjbWUgQ28xETAPBgNVBAMTCEpvbiBT
bm93MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDK6NU0R0eiCYVquU4RcjKc
LzGfx0aa1lMr2TnLQUSeLFZHFxsyyMXXuMPig3HK4A7SGFHupO+/1H/sL4xpH5zg
8+Zg2r8xnnney7abxcuv0uATWSIeKlNnb1ZO1BAxFnESc3GtyOCr2dUwZHX5mRVP
+Zxp2ni5qHNraf3wE2VPIQIDAQABoxIwEDAOBgNVHQ8BAf8EBAMCAKAwCwYJKoZI
hvcNAQELA4GBAIr2F7wsqmEU/J/kLyrCgEVXgaV/sKZq4pPNnzS0tBYk8fkV3V18
sBJyHKRLL/wFZASvzDcVGCplXyMdAOCyfd8jO3F9Ac/xdlz10RrHJT75hNu3a7/n
9KNwKhfN4A1CQv2x372oGjRhCW5bHNCWx4PIVeNzCyq/KZhyY9sxHE6f
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIICXgIBAAKBgQDK6NU0R0eiCYVquU4RcjKcLzGfx0aa1lMr2TnLQUSeLFZHFxsy
yMXXuMPig3HK4A7SGFHupO+/1H/sL4xpH5zg8+Zg2r8xnnney7abxcuv0uATWSIe
KlNnb1ZO1BAxFnESc3GtyOCr2dUwZHX5mRVP+Zxp2ni5qHNraf3wE2VPIQIDAQAB
AoGBALyvnSt7KUquDen7nXQtvJBudnf9KFPt//OjkdHHxNZNpoF/JCSqfQeoYkeu
MdAVYNLQGMiRifzZz4dDhA9xfUAuy7lcGQcMCxEQ1dwwuFaYkawbS0Tvy2PFlq2d
H5/HeDXU4EDJ3BZg0eYj2Bnkt1sJI35UKQSxblQ0MY2q0uFBAkEA5MMOogkgUx1C
67S1tFqMUSM8D0mZB0O5vOJZC5Gtt2Urju6vywge2ArExWRXlM2qGl8afFy2SgSv
Xk5eybcEiQJBAOMRwwbEoW5NYHuFFbSJyWll4n71CYuWuQOCzehDPyTb80WFZGLV
i91kFIjeERyq88eDE5xVB3ZuRiXqaShO/9kCQQCKOEkpInaDgZSjskZvuJ47kByD
6CYsO4GIXQMMeHML8ncFH7bb6AYq5ybJVb2NTU7QLFJmfeYuhvIm+xdOreRxAkEA
o5FC5Jg2FUfFzZSDmyZ6IONUsdF/i78KDV5nRv1R+hI6/oRlWNCtTNBv/lvBBd6b
dseUE9QoaQZsn5lpILEvmQJAZ0B+Or1rAYjnbjnUhdVZoy9kC4Zov+4UH3N/BtSy
KJRWUR0wTWfZBPZ5hAYZjTBEAFULaYCXlQKsODSp0M1aQA==
-----END PRIVATE KEY-----`
