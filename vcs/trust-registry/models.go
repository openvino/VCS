package main

// These structs intentionally mirror the JSON shape used by TrustBloc Wallet SDK mock trust registry.
// We keep them permissive to avoid tight coupling with a specific wallet-sdk version.

// EvaluationResult is returned by /wallet/interactions/{issuance|presentation}.
type EvaluationResult struct {
	// "allowed" or "denied"
	Result string `json:"result"`

	// Optional payload. When attestation is disabled, AttestationsRequired should be empty or omitted.
	Data *EvaluationData `json:"data,omitempty"`

	// Optional message for debugging.
	Message string `json:"message,omitempty"`
}

type EvaluationData struct {
	AttestationsRequired      []string `json:"attestations_required,omitempty"`
	ClientAttestationRequested bool     `json:"client_attestation_requested,omitempty"`
}

// IssuanceRequest is what the wallet sends to evaluate issuance.
type IssuanceRequest struct {
	// Wallet DID (if present). Different clients may name it differently.
	WalletDID string `json:"wallet_did,omitempty"`

	// Issuer DID (if present).
	IssuerDID string `json:"issuer_did,omitempty"`

	// Everything else (credential offers etc). We keep it loose.
	Raw map[string]any `json:"-"`
}

// PresentationRequest is what the wallet sends to evaluate presentation.
type PresentationRequest struct {
	WalletDID   string `json:"wallet_did,omitempty"`
	VerifierDID string `json:"verifier_did,omitempty"`
	Raw         map[string]any `json:"-"`
}

// Admin models
type TrustUpdateRequest struct {
	Trusted bool   `json:"trusted"`
	Reason  string `json:"reason,omitempty"`
}
