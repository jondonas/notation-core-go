package x509

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

// ValidateCodeSigningCertChain takes an ordered code-signing certificate chain and validates issuance from leaf to root
// Validates certificates according to this spec:
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#certificate-requirements
func ValidateCodeSigningCertChain(certChain []*x509.Certificate) error {
	return validateCertChain(certChain, x509.ExtKeyUsageCodeSigning)
}

// ValidateTimeStampingCertChain takes an ordered time-stamping certificate chain and validates issuance from leaf to root
// Validates certificates according to this spec:
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#certificate-requirements
func ValidateTimeStampingCertChain(certChain []*x509.Certificate) error {
	return validateCertChain(certChain, x509.ExtKeyUsageTimeStamping)
}

func validateCertChain(certChain []*x509.Certificate, expectedLeafEku x509.ExtKeyUsage) error {
	if len(certChain) < 2 {
		return errors.New("certificate chain must contain at least two certificates: a root and a leaf certificate")
	}

	for i, cert := range certChain {
		if i == len(certChain)-1 {
			if !isSelfSigned(cert) {
				return errors.New("certificate chain must end with a root certificate (root certificates are self-signed)")
			}
		} else {
			if isSelfSigned(cert) {
				return errors.New("certificate chain must not contain self-signed intermediate certificates")
			} else if nextCert := certChain[i+1]; !isIssuedBy(cert, nextCert) {
				return fmt.Errorf("certificate with subject %q is not issued by %q", cert.Subject, nextCert.Subject)
			}
		}

		if i == 0 {
			if err := validateLeafCertificate(cert, expectedLeafEku); err != nil {
				return err
			}
		} else {
			if err := validateCACertificate(cert, i-1); err != nil {
				return err
			}
		}
	}
	return nil
}

func isSelfSigned(cert *x509.Certificate) bool {
	return isIssuedBy(cert, cert)
}

func isIssuedBy(subject *x509.Certificate, issuer *x509.Certificate) bool {
	err := subject.CheckSignatureFrom(issuer)
	return err == nil && bytes.Equal(issuer.RawSubject, subject.RawIssuer)
}

func validateCACertificate(cert *x509.Certificate, expectedPathLen int) error {
	if err := validateCABasicConstraints(cert, expectedPathLen); err != nil {
		return err
	}
	return validateCAKeyUsage(cert)
}

func validateLeafCertificate(cert *x509.Certificate, expectedEku x509.ExtKeyUsage) error {
	if err := validateLeafBasicConstraints(cert); err != nil {
		return err
	}
	if err := validateLeafKeyUsage(cert); err != nil {
		return err
	}
	if err := validateExtendedKeyUsage(cert, expectedEku); err != nil {
		return err
	}
	return validateKeyLength(cert)
}

func validateCABasicConstraints(cert *x509.Certificate, expectedPathLen int) error {
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return errors.New("ca field in basic constraints must be present, critical, and set to true")
	}
	maxPathLen := cert.MaxPathLen
	isMaxPathLenPresent := maxPathLen > 0 || (maxPathLen == 0 && cert.MaxPathLenZero)
	if isMaxPathLenPresent && maxPathLen < expectedPathLen {
		return fmt.Errorf("expected path length of %d but certificate has path length %d instead", expectedPathLen, maxPathLen)
	}
	return nil
}

func validateLeafBasicConstraints(cert *x509.Certificate) error {
	if cert.BasicConstraintsValid && cert.IsCA {
		return errors.New("if the basic constraints extension is present, the ca field must be set to false")
	}
	return nil
}

func validateCAKeyUsage(cert *x509.Certificate) error {
	if err := validateKeyUsagePresent(cert); err != nil {
		return err
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("key usage must have the bit positions for key cert sign set")
	}
	return nil
}

func validateLeafKeyUsage(cert *x509.Certificate) error {
	if err := validateKeyUsagePresent(cert); err != nil {
		return err
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("key usage must have the bit positions for digital signature set")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 || cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		return errors.New("key usage must not have the bit positions for key cert sign or crl sign set")
	}
	return nil
}

func validateKeyUsagePresent(cert *x509.Certificate) error {
	keyUsageExtensionOid := []int{2, 5, 29, 15}

	var hasKeyUsageExtention bool
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(keyUsageExtensionOid) {
			if !ext.Critical {
				return errors.New("key usage extension must be marked critical")
			}
			hasKeyUsageExtention = true
			break
		}
	}
	if !hasKeyUsageExtention {
		return errors.New("key usage extension must be present")
	}
	return nil
}

func validateExtendedKeyUsage(cert *x509.Certificate, expectedEku x509.ExtKeyUsage) error {
	if len(cert.ExtKeyUsage) <= 0 {
		return nil
	}

	excludedEkus := []x509.ExtKeyUsage{x509.ExtKeyUsageAny, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageEmailProtection}
	if expectedEku == x509.ExtKeyUsageCodeSigning {
		excludedEkus = append(excludedEkus, x509.ExtKeyUsageTimeStamping)
	} else if expectedEku == x509.ExtKeyUsageTimeStamping {
		excludedEkus = append(excludedEkus, x509.ExtKeyUsageCodeSigning)
	}

	var hasExpectedEku bool
	for _, certEku := range cert.ExtKeyUsage {
		if certEku == expectedEku {
			hasExpectedEku = true
			continue
		}
		for _, excludedEku := range excludedEkus {
			if certEku == excludedEku {
				return fmt.Errorf("extended key usage must not contain %s eku", ekuToString(excludedEku))
			}
		}
	}

	if !hasExpectedEku {
		return fmt.Errorf("extended key usage must contain %s eku", ekuToString(expectedEku))
	}
	return nil
}

func validateKeyLength(cert *x509.Certificate) error {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return errors.New("rsa public key length must be 2048 bits or higher")
		}
	case *ecdsa.PublicKey:
		if key.Params().N.BitLen() < 256 {
			return errors.New("ecdsa public key length must be 256 bits or higher")
		}
	}
	return nil
}

func ekuToString(eku x509.ExtKeyUsage) string {
	switch eku {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "ServerAuth"
	case x509.ExtKeyUsageEmailProtection:
		return "EmailProtection"
	case x509.ExtKeyUsageCodeSigning:
		return "CodeSigning"
	case x509.ExtKeyUsageTimeStamping:
		return "TimeStamping"
	default:
		return fmt.Sprintf("%d", int(eku))
	}
}
