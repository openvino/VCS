package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
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

// -----------------------------------------------------------------------------
// Profiles parsing
// -----------------------------------------------------------------------------

type ProfilesRoot struct {
	Issuers []IssuerEntry `json:"issuers"`
}

type IssuerEntry struct {
	Issuer IssuerProfile `json:"issuer"`
}

type IssuerProfile struct {
	ID      string `json:"id"`
	Version string `json:"version"`

	CredentialTemplates []struct {
		Issuer string `json:"issuer"`
	} `json:"credentialTemplates"`
}

type IssuerInfo struct {
	ProfileID string
	Version   string
	DID       string
}

// -----------------------------------------------------------------------------
// did-resolver config
// -----------------------------------------------------------------------------

type ResolverConfig struct {
	Rules []ResolverRule `json:"rules"`
}

type ResolverRule struct {
	Pattern string `json:"pattern"`
	URL     string `json:"url,omitempty"`
}

// -----------------------------------------------------------------------------
// main
// -----------------------------------------------------------------------------

func main() {
	profilesPath := getenvDefault("VC_REST_PROFILES_JSON", "/var/www/VCS/profiles/profiles.json")
	domain := getenvDefault("DOMAIN", "https://yankee.openvino.org")

	didConfigurationOut := getenvDefault(
		"DID_CONFIGURATION_OUT",
		"/var/www/VCS/.well-known/did-configuration.json",
	)

	fixturesDidDir := getenvDefault(
		"FIXTURES_DID_DIR",
		"/var/www/VCS/vcs/test/bdd/fixtures/file-server/dids",
	)

	filesWebRoot := getenvDefault("FILES_WEB_ROOT", "/var/www/VCS/files")
	filesDidsDir := filepath.Join(filesWebRoot, "dids")

	resolverConfigPath := getenvDefault(
		"DID_RESOLVER_CONFIG",
		"/var/www/VCS/vcs/test/bdd/fixtures/did-resolver/config.json",
	)

	filesBaseURL := getenvDefault("FILES_BASE_URL", domain+"/files/dids")
	updateResolver := getenvDefault("UPDATE_DID_RESOLVER_CONFIG", "true") == "true"

	issuers, err := loadIssuers(profilesPath)
	exitOnErr("load profiles", err)
	if len(issuers) == 0 {
		log.Fatalf("no issuers found in %s", profilesPath)
	}

	exitOnErr("mkdir fixtures dids", os.MkdirAll(fixturesDidDir, 0o755))
	exitOnErr("mkdir files dids", os.MkdirAll(filesDidsDir, 0o755))

	var rc ResolverConfig
	var rcLoaded bool
	if updateResolver {
		rc, err = loadResolverConfig(resolverConfigPath)
		exitOnErr("load did-resolver config", err)
		rcLoaded = true
	}

	sort.SliceStable(issuers, func(i, j int) bool {
		return issuers[i].ProfileID < issuers[j].ProfileID
	})

	linkedDIDs := make([]interface{}, 0, len(issuers))
	createdDocs := 0

	for _, iss := range issuers {
		issuerDID := iss.DID
		verificationMethod := issuerDID + "#key-id"

		cred, jwk, err := createLinkedDomainCredential(
			issuerDID,
			verificationMethod,
			domain,
		)
		if err != nil {
			log.Printf("skip %s: %v", iss.ProfileID, err)
			continue
		}

		linkedDIDs = append(linkedDIDs, cred.JWTEnvelope.JWT)

		doc, err := buildDIDDocument(issuerDID, verificationMethod, domain, jwk)
		if err != nil {
			log.Printf("build DID doc failed (%s): %v", iss.ProfileID, err)
			continue
		}

		docBytes, _ := json.MarshalIndent(doc, "", "  ")

		// ---- did:web → nginx static paths
		if strings.HasPrefix(issuerDID, "did:web:") {
			rel, err := didWebDocPath(issuerDID)
			if err != nil {
				log.Printf("invalid did:web (%s): %v", iss.ProfileID, err)
				continue
			}
			publicPath := filepath.Join("/var/www/VCS", rel)
			exitOnErr("write did:web doc", writeFile(publicPath, docBytes))
			log.Printf("published did:web %s -> %s", issuerDID, publicPath)
			createdDocs++
			continue
		}

		// ---- legacy (did:ion, etc)
		filename := didFilename(issuerDID)
		publicPath := filepath.Join(filesDidsDir, filename)
		exitOnErr("write legacy did doc", writeFile(publicPath, docBytes))
		createdDocs++

		if updateResolver && rcLoaded {
			pattern := fmt.Sprintf("^(%s)$", regexp.QuoteMeta(issuerDID))
			targetURL := filesBaseURL + "/" + url.PathEscape(filename)
			if !hasRule(rc.Rules, pattern, targetURL) {
				rc.Rules = upsertRule(rc.Rules, ResolverRule{
					Pattern: pattern,
					URL:     targetURL,
				})
			}
		}
	}

	out := map[string]interface{}{
		"@context":    []string{didConfigurationContextURL},
		"linked_dids": linkedDIDs,
	}
	bytes, _ := json.MarshalIndent(out, "", "  ")
	exitOnErr("write did-configuration", writeFile(didConfigurationOut, bytes))

	if updateResolver && rcLoaded {
		rcBytes, _ := json.MarshalIndent(rc, "", "  ")
		exitOnErr("write did-resolver config", writeFile(resolverConfigPath, rcBytes))
		log.Printf("restart resolver: sudo systemctl restart did-resolver.service")
	}

	log.Printf("DONE issuers=%d did_docs=%d", len(issuers), createdDocs)
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func loadIssuers(path string) ([]IssuerInfo, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root ProfilesRoot
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, err
	}

	var out []IssuerInfo
	for _, e := range root.Issuers {
		if len(e.Issuer.CredentialTemplates) == 0 {
			continue
		}
		didStr := strings.TrimSpace(e.Issuer.CredentialTemplates[0].Issuer)
		if didStr == "" {
			continue
		}
		out = append(out, IssuerInfo{
			ProfileID: e.Issuer.ID,
			Version:   e.Issuer.Version,
			DID:       normalizeDID(didStr),
		})
	}
	return out, nil
}

func didWebDocPath(didStr string) (string, error) {
	const p = "did:web:"
	if !strings.HasPrefix(didStr, p) {
		return "", fmt.Errorf("not did:web")
	}
	rest := strings.TrimPrefix(didStr, p)
	parts := strings.Split(rest, ":")
	if len(parts) < 2 {
		return ".well-known/did.json", nil
	}
	return filepath.Join(append(parts[1:], "did.json")...), nil
}

func normalizeDID(id string) string {
	id = strings.TrimSpace(id)
	if strings.HasPrefix(id, "did:") {
		return id
	}
	return "did:ion:" + id
}

func didFilename(did string) string {
	s := strings.ReplaceAll(did, "/", "-")
	s = strings.ReplaceAll(s, ":", "-")
	return "did-" + s + ".json"
}

// -----------------------------------------------------------------------------
// VC + DID document
// -----------------------------------------------------------------------------

func createLinkedDomainCredential(
	issuerDID, verificationMethod, domain string,
) (*verifiable.Credential, *kmsjwk.JWK, error) {

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

	unsignedVC, err := verifiable.CreateCredential(
		buildCredentialContents(issuerDID, domain),
		nil,
	)
	if err != nil {
		return nil, nil, err
	}

	signed, err := cryptoSvc.SignCredential(signer, unsignedVC)
	if err != nil {
		return nil, nil, err
	}

	return signed, pubJWK, nil
}

func buildCredentialContents(issuerDID, domain string) verifiable.CredentialContents {
	now := time.Now().UTC()
	return verifiable.CredentialContents{
		Context: []string{w3CredentialsURL, didConfigurationContextURL},
		Types:   []string{vcTypeVerifiableCredential, vcTypeDomainLinkageCredential},
		Issuer:  &verifiable.Issuer{ID: issuerDID},
		Subject: []verifiable.Subject{{
			ID: issuerDID,
			CustomFields: map[string]interface{}{
				"origin": domain,
			},
		}},
		Issued:  utiltime.NewTime(now),
		Expired: utiltime.NewTime(now.Add(365 * 24 * time.Hour)),
	}
}

func buildDIDDocument(
	issuerDID, verificationMethod, domain string, jwk *kmsjwk.JWK,
) (*didDocument, error) {

	jwkBytes, _ := jwk.MarshalJSON()
	var jwkData map[string]interface{}
	_ = json.Unmarshal(jwkBytes, &jwkData)

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

// -----------------------------------------------------------------------------
// DID doc structs
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// VDR
// -----------------------------------------------------------------------------

type staticVDR struct{ doc *did.Doc }

func (s *staticVDR) Resolve(string, ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	return &did.DocResolution{DIDDocument: s.doc}, nil
}
func (s *staticVDR) Create(string, *did.Doc, ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	return nil, errors.New("not supported")
}
func (s *staticVDR) Update(*did.Doc, ...vdrapi.DIDMethodOption) error { return errors.New("not supported") }
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

// -----------------------------------------------------------------------------
// infra utils
// -----------------------------------------------------------------------------

func loadResolverConfig(path string) (ResolverConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ResolverConfig{}, err
	}
	var rc ResolverConfig
	if err := json.Unmarshal(b, &rc); err != nil {
		return ResolverConfig{}, err
	}
	if rc.Rules == nil {
		rc.Rules = []ResolverRule{}
	}
	return rc, nil
}

func hasRule(r []ResolverRule, p, u string) bool {
	for _, e := range r {
		if e.Pattern == p && e.URL == u {
			return true
		}
	}
	return false
}

func upsertRule(r []ResolverRule, rule ResolverRule) []ResolverRule {
	for i := range r {
		if r[i].Pattern == rule.Pattern {
			r[i].URL = rule.URL
			return r
		}
	}
	if len(r) <= 1 {
		return append(r, rule)
	}
	out := append([]ResolverRule{r[0], rule}, r[1:]...)
	return out
}

func createLocalKMS() (*kms.KeyManager, error) {
	cfg := &kms.Config{
		KMSType:   kms.Local,
		DBType:   getenvOrFail("VC_REST_DEFAULT_KMS_SECRETS_DATABASE_TYPE"),
		DBURL:    getenvOrFail("VC_REST_DEFAULT_KMS_SECRETS_DATABASE_URL"),
		DBName:   getenvOrFail("VC_REST_DEFAULT_KMS_SECRETS_DATABASE_PREFIX"),
		MasterKey: getenvOrFail("VC_REST_LOCAL_KMS_MASTER_KEY"),
	}
	return kms.NewAriesKeyManager(cfg, nil)
}

func getenvDefault(n, d string) string {
	if v := os.Getenv(n); v != "" {
		return v
	}
	return d
}

func getenvOrFail(n string) string {
	if v := os.Getenv(n); v == "" {
		log.Fatalf("env var %s required", n)
	}
	return os.Getenv(n)
}

func exitOnErr(msg string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
