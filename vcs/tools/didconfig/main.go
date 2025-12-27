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

type ProfilesRoot struct {
	Issuers []IssuerEntry `json:"issuers"`
}

type IssuerEntry struct {
	Issuer IssuerProfile `json:"issuer"`
}

type IssuerProfile struct {
	ID      string                 `json:"id"`
	Version string                 `json:"version"`
	Raw     map[string]interface{} `json:"-"`
}

type ResolverConfig struct {
	Rules []ResolverRule `json:"rules"`
}

type ResolverRule struct {
	Pattern string `json:"pattern"`
	URL     string `json:"url,omitempty"`
}

func main() {
	// === Defaults “de tu server” ===
	profilesPath := getenvDefault("VC_REST_PROFILES_JSON", "/var/www/VCS/profiles/profiles.json")
	domain := getenvDefault("DOMAIN", "https://yankee.openvino.org")

	// did-configuration.json (lo que consume wallets para Domain Linkage)
	didConfigurationOut := getenvDefault("DID_CONFIGURATION_OUT", "/var/www/VCS/.well-known/did-configuration.json")

	// donde generás fixtures DID docs (lo que vos ya venías haciendo)
	fixturesDidDir := getenvDefault("FIXTURES_DID_DIR", "/var/www/VCS/vcs/test/bdd/fixtures/file-server/dids")

	// docroot real que sirve Nginx para /files/dids/*
	filesWebRoot := getenvDefault("FILES_WEB_ROOT", "/var/www/VCS/files")
	filesDidsDir := filepath.Join(filesWebRoot, "dids")

	// config del did-resolver (docker mount)
	resolverConfigPath := getenvDefault("DID_RESOLVER_CONFIG", "/var/www/VCS/vcs/test/bdd/fixtures/did-resolver/config.json")

	// URL externa que el resolver debe usar para servir docs estáticos
	filesBaseURL := getenvDefault("FILES_BASE_URL", domain+"/files/dids")

	// generar también reglas del resolver
	updateResolver := getenvDefault("UPDATE_DID_RESOLVER_CONFIG", "true") == "true"

	issuers, err := loadIssuers(profilesPath)
	exitOnErr("load profiles", err)
	if len(issuers) == 0 {
		log.Fatalf("no issuers found in %s", profilesPath)
	}

	// Crea dirs
	exitOnErr("mkdir fixtures dids", os.MkdirAll(fixturesDidDir, 0o755))
	exitOnErr("mkdir files dids", os.MkdirAll(filesDidsDir, 0o755))

	linkedDIDs := make([]interface{}, 0, len(issuers))
	createdDocs := 0
	createdLinks := 0

	// cargá resolver config si lo vamos a tocar
	var rc ResolverConfig
	var rcLoaded bool
	if updateResolver {
		rc, err = loadResolverConfig(resolverConfigPath)
		exitOnErr("load did-resolver config", err)
		rcLoaded = true
	}

	// ordenar estable por issuer ID para reproducibilidad
	sort.SliceStable(issuers, func(i, j int) bool { return issuers[i].ID < issuers[j].ID })

	for _, iss := range issuers {
		issuerDID := normalizeDID(iss.ID)
		verificationMethod := issuerDID + "#key-id"

		// 1) linked_dids (JWT VC Domain Linkage)
		cred, jwk, err := createLinkedDomainCredential(issuerDID, verificationMethod, domain)
		if err != nil {
			log.Printf("skip issuer %s (%s): create credential failed: %v", iss.ID, iss.Version, err)
			continue
		}
		linkedDIDs = append(linkedDIDs, cred.JWTEnvelope.JWT)
		createdLinks++

		// 2) DID Document (fixture)
		doc, err := buildDIDDocument(issuerDID, verificationMethod, domain, jwk)
		if err != nil {
			log.Printf("warn issuer %s: build did doc failed: %v", iss.ID, err)
			continue
		}
		docBytes, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			log.Printf("warn issuer %s: marshal did doc failed: %v", iss.ID, err)
			continue
		}

		filename := didFilename(issuerDID)

		fixturePath := filepath.Join(fixturesDidDir, filename)

		if err := writeFile(fixturePath, docBytes); err != nil {
			log.Printf("warn issuer %s: write fixture did doc failed: %v", iss.ID, err)
			continue
		}
		log.Printf("did document written to %s", fixturePath)

		// 3) copiar al docroot de /files/dids
		publicPath := filepath.Join(filesDidsDir, filename)
		if err := writeFile(publicPath, docBytes); err != nil {
			log.Printf("warn issuer %s: write public did doc failed: %v", iss.ID, err)
			continue
		}
		createdDocs++
		log.Printf("did document published to %s", publicPath)

		// 4) asegurar regla en did-resolver/config.json
		if updateResolver && rcLoaded {
			pattern := fmt.Sprintf("^(%s)$", regexp.QuoteMeta(issuerDID))
			targetURL := filesBaseURL + "/" + url.PathEscape(filename)

			if !hasRule(rc.Rules, pattern, targetURL) {
				rc.Rules = upsertRule(rc.Rules, ResolverRule{
					Pattern: pattern,
					URL:     targetURL,
				})
				log.Printf("did-resolver rule upserted: %s -> %s", pattern, targetURL)
			}
		}
	}

	if createdLinks == 0 {
		log.Fatalf("no issuers could be processed from %s", profilesPath)
	}

	// 5) escribir did-configuration.json
	out := map[string]interface{}{
		"@context":    []string{didConfigurationContextURL},
		"linked_dids": linkedDIDs,
	}
	bytes, err := json.MarshalIndent(out, "", "  ")
	exitOnErr("marshal did-configuration json", err)
	exitOnErr("write did-configuration file", writeFile(didConfigurationOut, bytes))
	log.Printf("did-configuration written to %s (linked_dids=%d)", didConfigurationOut, len(linkedDIDs))

	// 6) escribir did-resolver/config.json actualizado (si aplica)
	if updateResolver && rcLoaded {
		rcBytes, err := json.MarshalIndent(rc, "", "  ")
		exitOnErr("marshal did-resolver config", err)
		exitOnErr("write did-resolver config", writeFile(resolverConfigPath, rcBytes))
		log.Printf("did-resolver config updated at %s", resolverConfigPath)
		log.Printf("NOTE: restart did-resolver.service to apply: sudo systemctl restart did-resolver.service")
	}

	log.Printf("DONE: issuers=%d linked=%d did_docs_published=%d", len(issuers), createdLinks, createdDocs)
}

func loadIssuers(path string) ([]IssuerProfile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root ProfilesRoot
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, err
	}
	out := make([]IssuerProfile, 0, len(root.Issuers))
	for _, e := range root.Issuers {
		id := strings.TrimSpace(e.Issuer.ID)
		if id == "" {
			continue
		}
		out = append(out, IssuerProfile{
			ID:      id,
			Version: strings.TrimSpace(e.Issuer.Version),
		})
	}
	return out, nil
}

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

func hasRule(rules []ResolverRule, pattern, url string) bool {
	for _, r := range rules {
		if r.Pattern == pattern && r.URL == url {
			return true
		}
	}
	return false
}

// upsert: si existe pattern lo actualiza; si no existe lo inserta “arriba” (después de la primera regla si hay)
func upsertRule(rules []ResolverRule, rule ResolverRule) []ResolverRule {
	for i := range rules {
		if rules[i].Pattern == rule.Pattern {
			rules[i].URL = rule.URL
			return rules
		}
	}
	// Inserción: después de la primera regla (mantiene tu orden actual: primero estáticos, luego did:key/web)
	if len(rules) <= 1 {
		return append(rules, rule)
	}
	out := make([]ResolverRule, 0, len(rules)+1)
	out = append(out, rules[0])
	out = append(out, rule)
	out = append(out, rules[1:]...)
	return out
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
	now := time.Now().UTC()
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
		Issued:  utiltime.NewTime(now),
		Expired: utiltime.NewTime(now.Add(365 * 24 * time.Hour)),
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

// normalizeDID makes issuer IDs flexible:
// - If profiles.json provides a full DID (e.g. did:web:..., did:ion:..., did:pkh:...), use it as-is.
// - If it provides a bare ION suffix (legacy), prefix it with did:ion:.
func normalizeDID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return id
	}
	if strings.HasPrefix(id, "did:") {
		return id
	}
	// Legacy behavior: profiles used to store only the ION suffix.
	return "did:ion:" + id
}

// didFilename turns a DID into a stable, filesystem-safe filename.
// Example: did:web:yankee.openvino.org -> did-did-web-yankee.openvino.org.json
func didFilename(did string) string {
	// keep dots (domain) but replace separators that are awkward in filenames
	s := strings.ReplaceAll(did, "/", "-")
	s = strings.ReplaceAll(s, ":", "-")
	return "did-" + s + ".json"
}

func getenvDefault(name, def string) string {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	return v
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
