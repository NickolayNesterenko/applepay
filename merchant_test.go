package applepay

import (
	"os"
	"testing"

	"crypto/tls"

	. "github.com/smartystreets/goconvey/convey"
)

func TestNew(t *testing.T) {

	if _, err := os.Stat("tests/certs/cert-merchant.crt"); os.IsNotExist(err) {
		t.Skip()
		return
	}
	if _, err := os.Stat("tests/certs/cert-processing.crt"); os.IsNotExist(err) {
		t.Skip()
		return
	}

	Convey("Invalid certificates are rejected", t, func() {
		m, err := New(
			IDFromString("merchant.com.processout.test"),
			MerchantPemCertificateLocation(
				"tests/certs/does-not-exist.crt",
				"tests/certs/does-not-exist-key.pem",
			),
		)

		Convey("m should be nil", func() {
			So(m, ShouldBeNil)
		})

		Convey("err should be correct", func() {
			So(err.Error(), ShouldStartWith, "error loading the certificate")
		})
	})

	Convey("Checks pass with our EC test configuration", t, func() {
		m, err := New(
			IDFromString("merchant.com.processout.test"),
			MerchantPemCertificateLocation(
				"tests/certs/cert-merchant.crt",
				"tests/certs/cert-merchant-key.pem",
			),
			ProcessingPemCertificateLocation(
				"tests/certs/cert-processing.crt",
				"tests/certs/cert-processing-key.pem",
			),
		)

		Convey("m should not be nil", func() {
			So(m, ShouldNotBeNil)
		})

		Convey("err should be nil", func() {
			So(err, ShouldBeNil)
		})
	})

	Convey("Checks pass with our RSA test configuration", t, func() {
		m, err := New(
			IDFromString("merchant.com.processout.test-rsa"),
			MerchantPemCertificateLocation(
				"tests/certs/cert-merchant-rsa.crt",
				"tests/certs/cert-merchant-rsa-key.pem",
			),
			ProcessingPemCertificateLocation(
				"tests/certs/cert-processing-rsa.crt",
				"tests/certs/cert-processing-rsa-key.pem",
			),
		)

		Convey("m should not be nil", func() {
			So(m, ShouldNotBeNil)
		})

		Convey("err should be nil", func() {
			So(err, ShouldBeNil)
		})
	})
}

func TestMerchantCertificates(t *testing.T) {
	if _, err := os.Stat("tests/certs/cert-merchant.crt"); os.IsNotExist(err) {
		t.Skip()
		return
	}
	if _, err := os.Stat("tests/certs/cert-processing.crt"); os.IsNotExist(err) {
		t.Skip()
		return
	}

	Convey("Loading an EC key does not work", t, func() {
		err := MerchantPemCertificateLocation(
			"tests/certs/cert-processing.crt",
			"tests/certs/cert-processing-key.pem",
		)(&Merchant{id: []byte("merchant.com.processout.test")})

		Convey("err should be correct", func() {
			So(err.Error(), ShouldStartWith, "merchant key should be RSA")
		})
	})

	Convey("Merchant ID must be correct", t, func() {
		err := MerchantPemCertificateLocation(
			"tests/certs/cert-merchant.crt",
			"tests/certs/cert-merchant-key.pem",
		)(&Merchant{id: []byte("merchant.com.processout.test.incorrect")})

		Convey("err should be correct", func() {
			So(err.Error(), ShouldStartWith, "invalid merchant certificate or merchant ID")
		})
	})

	Convey("Valid certificates work", t, func() {
		m := &Merchant{id: []byte("merchant.com.processout.test")}
		err := MerchantPemCertificateLocation(
			"tests/certs/cert-merchant.crt",
			"tests/certs/cert-merchant-key.pem",
		)(m)

		Convey("err should be nil", func() {
			So(err, ShouldBeNil)
		})

		Convey("merchantCertificateTLS should not be empty", func() {
			So(m.merchantCertificateTLS, ShouldNotResemble, tls.Certificate{})
		})
	})
}

func TestProcessingCertificates(t *testing.T) {
	if _, err := os.Stat("tests/certs/cert-merchant.crt"); os.IsNotExist(err) {
		t.Skip()
		return
	}
	if _, err := os.Stat("tests/certs/cert-processing.crt"); os.IsNotExist(err) {
		t.Skip()
		return
	}

	Convey("Merchant ID must be correct", t, func() {
		err := ProcessingPemCertificateLocation(
			"tests/certs/cert-processing.crt",
			"tests/certs/cert-processing-key.pem",
		)(&Merchant{id: []byte("merchant.com.processout.test.incorrect")})

		Convey("err should be correct", func() {
			So(err.Error(), ShouldStartWith, "invalid processing certificate or merchant ID")
		})
	})

	Convey("Valid certificates work", t, func() {
		m := &Merchant{id: []byte("merchant.com.processout.test")}
		err := ProcessingPemCertificateLocation(
			"tests/certs/cert-processing.crt",
			"tests/certs/cert-processing-key.pem",
		)(m)

		Convey("err should be nil", func() {
			So(err, ShouldBeNil)
		})

		Convey("merchantCertificateTLS should not be empty", func() {
			So(m.merchantCertificateTLS, ShouldNotResemble, tls.Certificate{})
		})
	})
}
