package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"time"
)

type (
	// SAML Response structure
	Response struct {
		XMLName      xml.Name
		SAMLP        string `xml:"xmlns:samlp,attr"`
		SAML         string `xml:"xmlns:saml,attr"`
		Destination  string `xml:"Destination,attr"`
		ID           string `xml:"ID,attr"`
		Version      string `xml:"Version,attr"`
		IssueInstant string `xml:"IssueInstant,attr"`
		InResponseTo string `xml:"InResponseTo,attr"`

		Issuer    Issuer    `xml:"Issuer"`
		Signature Signature `xml:"Signature,omitempty"`
		Status    Status    `xml:"Status"`
		Assertion Assertion `xml:"Assertion"`

		originalString string
	}

	// SAML response assertion
	Assertion struct {
		XMLName            xml.Name
		ID                 string `xml:"ID,attr"`
		Version            string `xml:"Version,attr"`
		XS                 string `xml:"xmlns:xs,attr"`
		XSI                string `xml:"xmlns:xsi,attr"`
		IssueInstant       string `xml:"IssueInstant,attr"`
		Issuer             Issuer `xml:"Issuer"`
		Subject            Subject
		Conditions         Conditions
		AuthnStatement     AuthnStatement
		AttributeStatement AttributeStatement
		Signature          *Signature `xml:"ds:Signature,omitempty"`
	}

	Conditions struct {
		XMLName      xml.Name
		NotBefore    string `xml:",attr"`
		NotOnOrAfter string `xml:",attr"`
	}

	AuthnStatement struct {
		XMLName             xml.Name
		AuthnInstant        string       `xml:",attr"`
		SessionNotOnOrAfter string       `xml:",attr"`
		SessionIndex        string       `xml:",attr"`
		Context             AuthnContext `xml:"saml:AuthnContext"`
	}

	AuthnContext struct {
		ClassRef string `xml:"saml:AuthnContextClassRef"`
	}

	Status struct {
		XMLName    xml.Name
		StatusCode StatusCode `xml:"StatusCode"`
	}

	NameID struct {
		XMLName xml.Name
		Format  string `xml:",attr"`
		Value   string `xml:",innerxml"`
	}

	StatusCode struct {
		XMLName xml.Name
		Value   string `xml:",attr"`
	}

	AttributeValue struct {
		XMLName xml.Name
		Type    string `xml:"xsi:type,attr"`
		Value   string `xml:",innerxml"`
	}

	Attribute struct {
		XMLName         xml.Name
		Name            string           `xml:",attr"`
		FriendlyName    string           `xml:",attr,omitempty"`
		NameFormat      string           `xml:",attr,omitempty"`
		AttributeValues []AttributeValue `xml:"AttributeValue"`
	}

	AttributeStatement struct {
		XMLName    xml.Name
		Attributes []Attribute `xml:"Attribute"`
	}
)

const (
	RESP_STATUS_SUCCESS                    = "urn:oasis:names:tc:SAML:2.0:status:Success"
	RESP_STATUS_REQUESTER                  = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	RESP_STATUS_RESPONDER                  = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	RESP_STATUS_VERSION_MISMATCH           = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
	RESP_STATUS_AUTHN_FAILED               = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
	RESP_STATUS_INVALID_ATTR_NAME_OR_VALUE = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"
	RESP_STATUS_INVALID_NAMEID_POLICY      = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"
	RESP_STATUS_NO_AUTHN_CONTEXT           = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"
	RESP_STATUS_NO_AVAILABLE_IDP           = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP"
	RESP_STATUS_NO_PASSIVE                 = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"
	RESP_STATUS_NO_SUPPORTED_IDP           = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP"
	RESP_STATUS_PARTIAL_LOGOUT             = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
	RESP_STATUS_PROXY_COUNT_EXCEEDED       = "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded"
	RESP_STATUS_REQUEST_DENIED             = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
	RESP_STATUS_REQUEST_UNSUPPORTED        = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"
	RESP_STATUS_REQUEST_VERSION_DEPRECATED = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated"
	RESP_STATUS_REQUEST_VERSION_TOO_HIGH   = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"
	RESP_STATUS_REQUEST_VERSION_TOO_LOW    = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow"
	RESP_STATUS_RESOURCE_NOT_RECOGNIZED    = "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized"
	RESP_STATUS_TOO_MANY_RESPONSES         = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses"
	RESP_STATUS_UNKNOWN_ATTR_PROFILE       = "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile"
	RESP_STATUS_UNKNOWN_PRINCIPAL          = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"
	RESP_STATUS_UNSUPPORTED_BINDING        = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"
)

var (
	ERR_RESP_UNSUPPORT_VERSION = errors.New("Unsupport saml version!")
	ERR_RESP_NEED_ID           = errors.New("Missing ID attribute on SAML Response")
	ERR_RESP_NEED_ASSERTION    = errors.New("Need Assertions!")
	ERR_RESP_NEED_SIGNATURE    = errors.New("Need signature!")
	ERR_RESP_DEST_MISMATH      = errors.New("Destination mismath!")
	ERR_RESP_METHOD_WRONG      = errors.New("Wrong assertion method!")
	ERR_RESP_RECIP_MISMATH     = errors.New("Subject recipient mismatch!")
	ERR_RESP_ASSERTION_EXPIRED = errors.New("Assertion has expired!")
)

func ParseCompressedEncodedResponse(b64ResponseXML string) (*Response, error) {
	authnResponse := Response{}
	compressedXML, err := base64.StdEncoding.DecodeString(b64ResponseXML)
	if err != nil {
		return nil, err
	}
	bXML := decompress(compressedXML)
	err = xml.Unmarshal(bXML, &authnResponse)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	authnResponse.originalString = string(bXML)
	return &authnResponse, nil

}

func ParseEncodedResponse(b64ResponseXML string) (*Response, error) {
	response := Response{}
	bytesXML, err := base64.StdEncoding.DecodeString(b64ResponseXML)
	if err != nil {
		return nil, err
	}
	err = xml.Unmarshal(bytesXML, &response)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	response.originalString = string(bytesXML)
	// fmt.Println(response.originalString)
	return &response, nil
}

func (r *Response) Validate(s *ServiceProviderSettings) error {
	if r.Version != "2.0" {
		return ERR_RESP_UNSUPPORT_VERSION
	}

	if len(r.ID) == 0 {
		return ERR_RESP_NEED_ID
	}

	if len(r.Assertion.ID) == 0 {
		return ERR_RESP_NEED_ASSERTION
	}

	if len(r.Signature.SignatureValue.Value) == 0 {
		return ERR_RESP_NEED_SIGNATURE
	}

	if r.Destination != s.AssertionConsumerServiceURL {
		return ERR_RESP_DEST_MISMATH
	}

	if r.Assertion.Subject.SubjectConfirmation.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
		return ERR_RESP_METHOD_WRONG
	}

	if r.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != s.AssertionConsumerServiceURL {
		return ERR_RESP_RECIP_MISMATH
	}

	err := VerifyResponseSignature(r.originalString, s.IDPPublicCertPath)
	if err != nil {
		return err
	}

	//CHECK TIMES
	expires := r.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter
	notOnOrAfter, e := time.Parse(time.RFC3339, expires)
	if e != nil {
		return e
	}
	if notOnOrAfter.Before(time.Now()) {
		return ERR_RESP_ASSERTION_EXPIRED
	}

	return nil
}

// NewSignedResponse create a new signed response
func NewSignedResponse() *Response {
	return &Response{
		XMLName: xml.Name{
			Local: "samlp:Response",
		},
		SAMLP:        "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:         "urn:oasis:names:tc:SAML:2.0:assertion",
		ID:           ID(),
		Version:      "2.0",
		IssueInstant: time.Now().UTC().Format(time.RFC3339Nano),
		Signature: Signature{
			XMLName: xml.Name{
				Local: "ds:Signature",
			},
			SAMLSIG: _SAMLSIG,
			SignedInfo: SignedInfo{
				XMLName: xml.Name{
					Local: "ds:SignedInfo",
				},
				CanonicalizationMethod: CanonicalizationMethod{
					XMLName: xml.Name{
						Local: "ds:CanonicalizationMethod",
					},
					Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
				},
				SignatureMethod: SignatureMethod{
					XMLName: xml.Name{
						Local: "ds:SignatureMethod",
					},
					Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
				},
				SamlsigReference: SamlsigReference{
					XMLName: xml.Name{
						Local: "ds:Reference",
					},
					URI: "", // caller must populate "#" + ar.Id,
					Transforms: Transforms{
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
					},
					DigestMethod: DigestMethod{
						XMLName: xml.Name{
							Local: "ds:DigestMethod",
						},
						Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
					},
					DigestValue: DigestValue{
						XMLName: xml.Name{
							Local: "ds:DigestValue",
						},
					},
				},
			},
			SignatureValue: SignatureValue{
				XMLName: xml.Name{
					Local: "ds:SignatureValue",
				},
			},
			KeyInfo: KeyInfo{
				XMLName: xml.Name{
					Local: "ds:KeyInfo",
				},
				X509Data: X509Data{
					XMLName: xml.Name{
						Local: "ds:X509Data",
					},
					X509Certificate: X509Certificate{
						XMLName: xml.Name{
							Local: "ds:X509Certificate",
						},
						Cert: "", // caller must populate cert,
					},
				},
			},
		},
		Status: Status{
			XMLName: xml.Name{
				Local: "samlp:Status",
			},
			StatusCode: StatusCode{
				XMLName: xml.Name{
					Local: "samlp:StatusCode",
				},
				Value: RESP_STATUS_SUCCESS,
			},
		},
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
		},
		Assertion: Assertion{
			XMLName: xml.Name{
				Local: "saml:Assertion",
			},
			XS:           "http://www.w3.org/2001/XMLSchema",
			XSI:          "http://www.w3.org/2001/XMLSchema-instance",
			Version:      "2.0",
			ID:           ID(),
			IssueInstant: time.Now().UTC().Format(time.RFC3339),
			Issuer: Issuer{
				XMLName: xml.Name{
					Local: "saml:Issuer",
				},
				Url: "", // caller must populate ar.AppSettings.AssertionConsumerServiceURL,
			},
			Subject: Subject{
				XMLName: xml.Name{
					Local: "saml:Subject",
				},
				NameID: NameID{
					XMLName: xml.Name{
						Local: "saml:NameID",
					},
					Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
					Value:  "",
				},
				SubjectConfirmation: SubjectConfirmation{
					XMLName: xml.Name{
						Local: "saml:SubjectConfirmation",
					},
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: SubjectConfirmationData{
						XMLName: xml.Name{
							Local: "saml:SubjectConfirmationData",
						},
						InResponseTo: "",
						NotOnOrAfter: time.Now().Add(time.Minute * 5).UTC().Format(time.RFC3339),
						Recipient:    "",
					},
				},
			},
			Conditions: Conditions{
				XMLName: xml.Name{
					Local: "saml:Conditions",
				},
				NotBefore:    time.Now().Add(time.Minute * -5).UTC().Format(time.RFC3339),
				NotOnOrAfter: time.Now().Add(time.Minute * 5).UTC().Format(time.RFC3339),
			},
			AttributeStatement: AttributeStatement{
				XMLName: xml.Name{
					Local: "saml:AttributeStatement",
				},
				Attributes: []Attribute{},
			},
			AuthnStatement: AuthnStatement{
				XMLName: xml.Name{
					Local: "saml:AuthnStatement",
				},
				AuthnInstant:        time.Now().UTC().Format(time.RFC3339),
				SessionNotOnOrAfter: time.Now().Add(time.Minute * 5).UTC().Format(time.RFC3339),
				SessionIndex:        ID(),
				Context: AuthnContext{
					ClassRef: "rn:oasis:names:tc:SAML:2.0:ac:classes:Password",
				},
			},
		},
	}
}

// set assertion NameID
func (r *Response) SetNameID(nameID string) {
	r.Assertion.Subject.NameID.Value = nameID
}

// set repsonse to
func (r *Response) SetResponseTo(responseTo string) {
	r.InResponseTo = responseTo
}

// set response issuer(IdP)
func (r *Response) SetIssuer(issuer string) {
	r.Issuer.Url = issuer
	r.Assertion.Issuer.Url = issuer
}

// AddAttribute add strong attribute to the Response
func (r *Response) AddAttribute(name, value string) {
	r.Assertion.AttributeStatement.Attributes = append(r.Assertion.AttributeStatement.Attributes, Attribute{
		XMLName: xml.Name{
			Local: "saml:Attribute",
		},
		Name:       name,
		NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
		AttributeValues: []AttributeValue{
			{
				XMLName: xml.Name{
					Local: "saml:AttributeValue",
				},
				Type:  "xs:string",
				Value: value,
			},
		},
	})
}

func (r *Response) String() (string, error) {
	b, err := xml.MarshalIndent(r, "", "    ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (r *Response) SignedString(privateKeyPath string) (string, error) {
	s, err := r.String()
	if err != nil {
		return "", err
	}

	return SignResponse(s, privateKeyPath)
}

func (r *Response) EncodedSignedString(privateKeyPath string) (string, error) {
	signed, err := r.SignedString(privateKeyPath)
	if err != nil {
		return "", err
	}
	b64XML := base64.StdEncoding.EncodeToString([]byte(signed))
	return b64XML, nil
}

func (r *Response) CompressedEncodedSignedString(privateKeyPath string) (string, error) {
	signed, err := r.SignedString(privateKeyPath)
	if err != nil {
		return "", err
	}
	compressed := compress([]byte(signed))
	b64XML := base64.StdEncoding.EncodeToString(compressed)
	return b64XML, nil
}

// GetAttributeValue by Name or by FriendlyName. Return blank string if not found
func (r *Response) GetAttributeValue(name string) string {
	for _, attr := range r.Assertion.AttributeStatement.Attributes {
		if attr.Name == name || attr.FriendlyName == name {
			return attr.AttributeValues[0].Value
		}
	}
	return ""
}

// GetAttributeValues returns attribute's values
func (r *Response) GetAttributeValues(name string) []string {
	var values []string
	for _, attr := range r.Assertion.AttributeStatement.Attributes {
		if attr.Name == name || attr.FriendlyName == name {
			for _, v := range attr.AttributeValues {
				values = append(values, v.Value)
			}
		}
	}
	return values
}
