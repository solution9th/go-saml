package saml

import "encoding/xml"

type Issuer struct {
	XMLName xml.Name
	Format  string `xml:"xmlns:saml,attr,omitempty"`
	Url     string `xml:",innerxml"`
}

// NewIssuer will create a new issuer
func NewIssuer(issuer string) *Issuer {
	return &Issuer{
		XMLName: xml.Name{
			Local: "saml:Issuer",
		},
		Url:    issuer,
		Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
	}
}

// structure of <Subject>
type (
	Subject struct {
		XMLName             xml.Name
		NameID              NameID
		SubjectConfirmation SubjectConfirmation
	}

	SubjectConfirmation struct {
		XMLName                 xml.Name
		Method                  string `xml:",attr"`
		SubjectConfirmationData SubjectConfirmationData
	}

	// It specifies additional data that allows the subject to be confirmed
	// or constrains the circumstances under which the act of subject confirmation can take place
	SubjectConfirmationData struct {
		XMLName      xml.Name
		InResponseTo string `xml:",attr,omitempty"`
		NotOnOrAfter string `xml:",attr,omitempty"`
		NotBefore    string `xml:",attr,omitempty"`
		Recipient    string `xml:",attr,omitempty"`
		Address      string `xml:",attr,omitempty"`
	}
)

type AuthnContextClassRef struct {
	XMLName   xml.Name
	SAML      string `xml:"xmlns:saml,attr"`
	Transport string `xml:",innerxml"`
}

type Signature struct {
	XMLName        xml.Name
	SAMLSIG        string `xml:"xmlns:ds,attr"`
	SignedInfo     SignedInfo
	SignatureValue SignatureValue
	KeyInfo        KeyInfo
}

func NewSignature() *Signature {

	sign := &Signature{
		SignedInfo: *NewSignedInfo(),
	}

	return sign
}

type SignedInfo struct {
	XMLName                xml.Name
	CanonicalizationMethod CanonicalizationMethod
	SignatureMethod        SignatureMethod
	SamlsigReference       SamlsigReference
}

func NewSignedInfo() *SignedInfo {

	signMethod := SignatureMethod{
		XMLName: xml.Name{
			Local: "ds:SignatureMethod",
		},
		Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
	}

	canonicalMethod := CanonicalizationMethod{
		XMLName: xml.Name{
			Local: "ds:CanonicalizationMethod",
		},
		Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
	}

	transforms := Transforms{
		XMLName: xml.Name{
			Local: "ds:Transforms",
		},
		Transform: []Transform{
			{
				XMLName: xml.Name{
					Local: "ds:Transform",
				},
				Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
			},
			{
				XMLName: xml.Name{
					Local: "ds:Transform",
				},
				Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
			},
		},
	}

	return &SignedInfo{
		SignatureMethod:        signMethod,
		CanonicalizationMethod: canonicalMethod,
		SamlsigReference: SamlsigReference{
			Transforms: transforms,
		},
	}
}

type SignatureValue struct {
	XMLName xml.Name
	Value   string `xml:",innerxml"`
}

type KeyInfo struct {
	XMLName  xml.Name
	X509Data X509Data `xml:",innerxml"`
}

type CanonicalizationMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type SignatureMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type SamlsigReference struct {
	XMLName      xml.Name
	URI          string       `xml:"URI,attr"`
	Transforms   Transforms   `xml:",innerxml"`
	DigestMethod DigestMethod `xml:",innerxml"`
	DigestValue  DigestValue  `xml:",innerxml"`
}

type X509Data struct {
	XMLName         xml.Name
	X509Certificate X509Certificate `xml:",innerxml"`
}

type Transforms struct {
	XMLName   xml.Name
	Transform []Transform
}

type DigestMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type DigestValue struct {
	XMLName xml.Name
}

type X509Certificate struct {
	XMLName xml.Name
	Cert    string `xml:",innerxml"`
}

type Transform struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type EntityDescriptor struct {
	XMLName  xml.Name
	DS       string `xml:"xmlns:ds,attr"`
	XMLNS    string `xml:"xmlns,attr"`
	MD       string `xml:"xmlns:md,attr"`
	EntityId string `xml:"entityID,attr"`

	Extensions      Extensions      `xml:"Extensions"`
	SPSSODescriptor SPSSODescriptor `xml:"SPSSODescriptor"`
}

type Extensions struct {
	XMLName xml.Name
	Alg     string `xml:"xmlns:alg,attr"`
	MDAttr  string `xml:"xmlns:mdattr,attr"`
	MDRPI   string `xml:"xmlns:mdrpi,attr"`

	EntityAttributes string `xml:"EntityAttributes"`
}

type SPSSODescriptor struct {
	XMLName                    xml.Name
	ProtocolSupportEnumeration string `xml:"protocolSupportEnumeration,attr"`
	SigningKeyDescriptor       KeyDescriptor
	EncryptionKeyDescriptor    KeyDescriptor
	// SingleLogoutService        SingleLogoutService `xml:"SingleLogoutService"`
	AssertionConsumerServices []AssertionConsumerService
}

type EntityAttributes struct {
	XMLName xml.Name
	SAML    string `xml:"xmlns:saml,attr"`
	// should be array??
	EntityAttributes []Attribute `xml:"Attribute"`
}

type SPSSODescriptors struct {
}

type KeyDescriptor struct {
	XMLName xml.Name
	Use     string  `xml:"use,attr"`
	KeyInfo KeyInfo `xml:"KeyInfo"`
}

type SingleLogoutService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type AssertionConsumerService struct {
	XMLName  xml.Name
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    string `xml:"index,attr"`
}
