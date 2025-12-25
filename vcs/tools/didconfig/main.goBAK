package main

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/trustbloc/did-go/doc/did"
	utiltime "github.com/trustbloc/did-go/doc/util/time"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	kmsjwk "github.com/trustbloc/kms-go/doc/jose/jwk"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/kms"
)

const (
	didConfigurationContextURL    = "https://identity.foundation/.well-known/did-configuration/v1"
	w3CredentialsURL              = "https://www.w3.org/2018/credentials/v1"
	vcTypeVerifiableCredential    = "VerifiableCredential"
	vcTypeDomainLinkageCredential = "DomainLinkageCredential"
)

func main() {
	const (
		issuerDID          = "did:ion:bank_issuer"
		verificationMethod = "did:ion:bank_issuer#key-id"
		domain             = "https://yankee.openvino.org"
		stagingFile        = "/var/www/VCS/.well-known/did-configuration.json"
		didDocFile         = "/var/www/VCS/vcs/test/bdd/fixtures/file-server/dids/did-ion-bank-issuer.json"
	)

	cred, jwk, err := createLinkedDomainCredential(issuerDID, verificationMethod, domain)
	exitOnErr("create credential", err)

	output := map[string]interface{}{
		"@context": []string{didConfigurationContextURL},
		"linked_dids": []interface{}{
			cred.JWTEnvelope.JWT,
		},
	}

	bytes, err := json.MarshalIndent(output, "", "  ")
	exitOnErr("marshal json", err)

	exitOnErr("write staging file", writeFile(stagingFile, bytes))
	log.Printf("did-configuration written to %s\n", stagingFile)

	doc, err := buildDIDDocument(issuerDID, verificationMethod, domain, jwk)
	exitOnErr("build did doc", err)

	docBytes, err := json.MarshalIndent(doc, "", "  ")
	exitOnErr("marshal did doc", err)

	exitOnErr("write did doc", writeFile(didDocFile, docBytes))
	log.Printf("did document written to %s\n", didDocFile)
}

func createLinkedDomainCredential(issuerDID, verificationMethod, domain string) (*verifiable.Credential, *kmsjwk.JWK, error) {
	km, err := createLocalKMS()
	if err != nil {
		return nil, nil, err
	}

	doc := newStaticDIDDoc(issuerDID, verificationMethod)
	cryptoSvc := crypto.New(&staticVDR{doc: doc}, nil)

	keyID, pubJWK, err := km.CreateJWKKey(kmsapi.ED25519Type)
	if err != nil {
		return nil, nil, err
	}

	signer := &vc.Signer{
		Format:        vcsverifiable.Jwt,
		DID:           issuerDID,
		Creator:       verificationMethod,
		KMSKeyID:      keyID,
		SignatureType: vcsverifiable.Ed25519Signature2018,
		KeyType:       kmsapi.ED25519Type,
		KMS:           km,
	}

	contents := buildCredentialContents(issuerDID, domain)

	unsignedVC, err := verifiable.CreateCredential(contents, nil)
	if err != nil {
		return nil, nil, err
	}

	signed, err := cryptoSvc.SignCredential(signer, unsignedVC)
	if err != nil {
		return nil, nil, err
	}

	return signed, pubJWK, nil
}

func createLocalKMS() (*kms.KeyManager, error) {
	cfg := &kms.Config{
		KMSType:           kms.Local,
		DBType:            getenvOrFail("VC_REST_DEFAULT_KMS_SECRETS_DATABASE_TYPE"),
		DBURL:             getenvOrFail("VC_REST_DEFAULT_KMS_SECRETS_DATABASE_URL"),
		DBName:            getenvOrFail("VC_REST_DEFAULT_KMS_SECRETS_DATABASE_PREFIX"),
		MasterKey:         getenvOrFail("VC_REST_LOCAL_KMS_MASTER_KEY"),
		SecretLockKeyPath: os.Getenv("VC_REST_LOCAL_KMS_SECRET_LOCK_KEY_PATH"),
	}

	return kms.NewAriesKeyManager(cfg, nil)
}

func buildCredentialContents(issuerDID, domain string) verifiable.CredentialContents {
	return verifiable.CredentialContents{
		Context: []string{
			w3CredentialsURL,
			didConfigurationContextURL,
		},
		Types: []string{
			vcTypeVerifiableCredential,
			vcTypeDomainLinkageCredential,
		},
		Issuer: &verifiable.Issuer{ID: issuerDID},
		Subject: []verifiable.Subject{{
			ID: issuerDID,
			CustomFields: map[string]interface{}{
				"origin": domain,
			},
		}},
		Issued:  utiltime.NewTime(time.Now().UTC()),
		Expired: utiltime.NewTime(time.Now().UTC().Add(365 * 24 * time.Hour)),
	}
}

func buildDIDDocument(issuerDID, verificationMethod, domain string, jwk *kmsjwk.JWK) (*didDocument, error) {
	jwkBytes, err := jwk.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var jwkData map[string]interface{}
	if err = json.Unmarshal(jwkBytes, &jwkData); err != nil {
		return nil, err
	}

	return &didDocument{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      issuerDID,
		VerificationMethod: []verificationMethodEntry{{
			ID:           verificationMethod,
			Type:         "JsonWebKey2020",
			Controller:   issuerDID,
			PublicKeyJWK: jwkData,
		}},
		Authentication:  []string{verificationMethod},
		AssertionMethod: []string{verificationMethod},
		Service: []serviceEntry{{
			ID:              issuerDID + "#linked-domain",
			Type:            "LinkedDomains",
			ServiceEndpoint: domain + "/.well-known/did-configuration.json",
		}},
	}, nil
}

type didDocument struct {
	Context            []string                  `json:"@context"`
	ID                 string                    `json:"id"`
	VerificationMethod []verificationMethodEntry `json:"verificationMethod"`
	Authentication     []string                  `json:"authentication"`
	AssertionMethod    []string                  `json:"assertionMethod"`
	Service            []serviceEntry            `json:"service"`
}

type verificationMethodEntry struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Controller   string                 `json:"controller"`
	PublicKeyJWK map[string]interface{} `json:"publicKeyJwk,omitempty"`
}

type serviceEntry struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

type staticVDR struct {
	doc *did.Doc
}

func (s *staticVDR) Resolve(string, ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	return &did.DocResolution{DIDDocument: s.doc}, nil
}
func (s *staticVDR) Create(string, *did.Doc, ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	return nil, errors.New("not supported")
}
func (s *staticVDR) Update(*did.Doc, ...vdrapi.DIDMethodOption) error {
	return errors.New("not supported")
}
func (s *staticVDR) Deactivate(string, ...vdrapi.DIDMethodOption) error {
	return errors.New("not supported")
}
func (s *staticVDR) Close() error { return nil }

func newStaticDIDDoc(issuerDID, verificationMethod string) *did.Doc {
	vm := did.VerificationMethod{
		ID:         verificationMethod,
		Type:       "JsonWebKey2020",
		Controller: issuerDID,
	}

	doc := &did.Doc{
		ID:                 issuerDID,
		VerificationMethod: []did.VerificationMethod{vm},
	}

	doc.Authentication = []did.Verification{{
		VerificationMethod: vm,
		Relationship:       did.Authentication,
	}}

	return doc
}

func getenvOrFail(name string) string {
	val := os.Getenv(name)
	if val == "" {
		log.Fatalf("env var %s is required", name)
	}
	return val
}

func exitOnErr(msg string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}

func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
