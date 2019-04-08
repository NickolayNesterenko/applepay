package applepay

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"

	"github.com/pkg/errors"
	"encoding/hex"
)

type (
	certificatePKCS12 struct {
		certificateX509 *x509.Certificate
		privateKey interface{}
	}

	Merchant struct {
		// General configuration
		id          []byte
		idHash      []byte
		displayName string
		domainName  string

		// Merchant Identity TLS Certificate
		merchantCertificateTLS *tls.Certificate

		// Payment Processing TLS Certificate
		processingCertificateTLS *tls.Certificate
		// Payment Processing X509 Certificate
		processingCertificatePKCS12 *certificatePKCS12

		cfgValidators []func(*Merchant) error
	}
)

var (
	// merchantIDHashOID is the ASN.1 object id of Apple's extension
	// for merchant ID hash in merchant/processing certificates
	merchantIDHashOID = mustParseASN1ObjectIdentifier(
		"1.2.840.113635.100.6.32",
	)
)

// New creates an instance of Merchant using the given configuration
func New(options ...func(*Merchant) error) (*Merchant, error) {
	m := &Merchant{
		cfgValidators: make([]func(*Merchant) error, 1),
	}
	m.cfgValidators[0] = func(m *Merchant) error {
		if m.id == nil {
			return errors.New("merchant id is not set")
		}
		return nil
	}

	for _, option := range options {
		err := option(m)
		if err != nil {
			return nil, err
		}
	}

	for _, validator := range m.cfgValidators {
		if err := validator(m); err != nil {
			return nil, err
		}
	}

	return m, nil
}

// MerchantStringID directly sets merchant id from string.
func IDFromString(merchantID string) func(*Merchant) error {
	return func(m *Merchant) error {
		m.id = []byte(merchantID)
		m.idHash = m.identifierHash()
		return nil
	}
}

// identifierHash hashes m.config.MerchantIdentifier with SHA-256
func (m *Merchant) identifierHash() []byte {
	h := sha256.New()
	h.Write(m.id)
	return h.Sum(nil)
}

func MerchantDisplayName(displayName string) func(*Merchant) error {
	return func(m *Merchant) error {
		m.displayName = displayName
		return nil
	}
}

func MerchantDomainName(domainName string) func(*Merchant) error {
	return func(m *Merchant) error {
		m.domainName = domainName
		return nil
	}
}

func MerchantCertificateTLS(cert tls.Certificate) func(*Merchant) error {
	return func(m *Merchant) error {
		m.merchantCertificateTLS = &cert
		m.cfgValidators = append(m.cfgValidators, func(m *Merchant) error {
			// Check that the certificate is RSA
			if _, ok := cert.PrivateKey.(*rsa.PrivateKey); !ok {
				return errors.New("merchant key should be RSA")
			}
			// Verify merchant ID
			hash, err := extractMerchantHash(cert)
			if err != nil {
				return errors.Wrap(err, "error reading the certificate")
			}
			if !bytes.Equal(hash, m.idHash) {
				return errors.New("invalid merchant certificate or merchant ID")
			}
			return nil
		})
		return nil
	}
}

func ProcessingCertificateTLS(cert tls.Certificate) func(*Merchant) error {
	return func(m *Merchant) error {
		m.processingCertificateTLS = &cert
		m.cfgValidators = append(m.cfgValidators, func(m *Merchant) error {
			// Verify merchant ID
			hash, err := extractMerchantHash(cert)
			if err != nil {
				return errors.Wrap(err, "error reading the certificate")
			}
			if !bytes.Equal(hash, m.idHash) {
				return errors.New("invalid processing certificate or merchant ID")
			}
			return nil
		})
		return nil
	}
}

// ProcessingCertificatePKCS12 parses base64 encoded PKCS12 certificate from string
// and sets merchant id from certificate extension if not set.
func ProcessingCertificatePKCS12(cert string, password string) func(*Merchant) error {
	return func(m *Merchant) error {
		certDecoded, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			return errors.Wrap(err, "cannot decode base64 data")
		}

		pkey, certificate, err := parsePKCS12Data(certDecoded, password)
		if err != nil {
			return err
		}

		m.processingCertificatePKCS12 = new(certificatePKCS12)
		m.processingCertificatePKCS12.certificateX509 = certificate
		m.processingCertificatePKCS12.privateKey = pkey

		if m.id == nil {
			if extValue, err := extractExtension(certificate, merchantIDHashOID); err == nil {
				m.id = extValue[2:]
				m.idHash = make([]byte, hex.DecodedLen(len(m.id)))
				_, err := hex.Decode(m.idHash, m.id)
				if err != nil {
					return errors.Wrap(err, "cannot decode merchant id to binary")
				}
			}
		}

		return nil
	}
}


func MerchantPemCertificateLocation(certLocation,
	keyLocation string) func(*Merchant) error {

	return loadCertificateTLS(certLocation, keyLocation, MerchantCertificateTLS)
}

func ProcessingPemCertificateLocation(certLocation,
	keyLocation string) func(*Merchant) error {

	return loadCertificateTLS(certLocation, keyLocation, ProcessingCertificateTLS)
}

func loadCertificateTLS(certLocation, keyLocation string, callback func(tls.Certificate) func(*Merchant) error) func(*Merchant) error {
	return func(m *Merchant) error {
		cert, err := tls.LoadX509KeyPair(certLocation, keyLocation)
		if err != nil {
			return errors.Wrap(err, "error loading the certificate")
		}
		return callback(cert)(m)
	}
}
