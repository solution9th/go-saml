package saml

import (
	"io/ioutil"
	"regexp"
	"strings"

	uuid "github.com/satori/go.uuid"
)

// ServiceProviderSettings provides settings to configure server acting as a SAML Service Provider.
// Expect only one IDP per SP in this configuration. If you need to configure multipe IDPs for an SP
// then configure multiple instances of this module
type ServiceProviderSettings struct {
	PublicCertPath              string
	PrivateKeyPath              string
	IDPSSOURL                   string
	IDPSSODescriptorURL         string
	IDPPublicCertPath           string
	AssertionConsumerServiceURL string
	SPSignRequest               bool

	hasInit       bool
	publicCert    string
	privateKey    string
	iDPPublicCert string
}

// ID generate a new V4 UUID
func ID() string {
	u := uuid.Must(uuid.NewV4())
	return "_" + u.String()
}

func loadCertificate(certPath string) (string, error) {
	b, err := ioutil.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	cert := string(b)

	re := regexp.MustCompile("---(.*)CERTIFICATE(.*)---")
	cert = re.ReplaceAllString(cert, "")
	cert = strings.Trim(cert, " \n")
	cert = strings.Replace(cert, "\n", "", -1)

	return cert, nil
}

type IdentityProviderSettings struct {
}

func (s *ServiceProviderSettings) Init() (err error) {
	if s.hasInit {
		return nil
	}
	s.hasInit = true

	if s.SPSignRequest {
		s.publicCert, err = loadCertificate(s.PublicCertPath)
		if err != nil {
			panic(err)
		}

		s.privateKey, err = loadCertificate(s.PrivateKeyPath)
		if err != nil {
			panic(err)
		}
	}

	s.iDPPublicCert, err = loadCertificate(s.IDPPublicCertPath)
	if err != nil {
		panic(err)
	}

	return nil
}

func (s *ServiceProviderSettings) PublicCert() string {
	if !s.hasInit {
		panic("Must call ServiceProviderSettings.Init() first")
	}
	return s.publicCert
}

func (s *ServiceProviderSettings) PrivateKey() string {
	if !s.hasInit {
		panic("Must call ServiceProviderSettings.Init() first")
	}
	return s.privateKey
}

func (s *ServiceProviderSettings) IDPPublicCert() string {
	if !s.hasInit {
		panic("Must call ServiceProviderSettings.Init() first")
	}
	return s.iDPPublicCert
}
