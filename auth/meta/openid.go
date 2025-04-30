package meta

// OpenIDConfiguration models the OpenID Provider Metadata as defined in
// OpenID Connect Discovery 1.0 (https://openid.net/specs/openid-connect-discovery-1_0.html)
//
// NOTE:
//   - All slices are nil by default; add values as needed.
//   - The "Extra" map preserves extension parameters that are not explicitly modeled here.
type OpenIDConfiguration struct {
	// REQUIRED
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	// RECOMMENDED
	UserinfoEndpoint       string   `json:"userinfo_endpoint,omitempty"`
	RegistrationEndpoint   string   `json:"registration_endpoint,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	ResponseModesSupported []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported    []string `json:"grant_types_supported,omitempty"`
	ACRValuesSupported     []string `json:"acr_values_supported,omitempty"`
	ClaimsSupported        []string `json:"claims_supported,omitempty"`
	ClaimTypesSupported    []string `json:"claim_types_supported,omitempty"`
	ClaimsLocalesSupported []string `json:"claims_locales_supported,omitempty"`
	UILocalesSupported     []string `json:"ui_locales_supported,omitempty"`
	ServiceDocumentation   string   `json:"service_documentation,omitempty"`
	OPPolicyURI            string   `json:"op_policy_uri,omitempty"`
	OPTosURI               string   `json:"op_tos_uri,omitempty"`

	// OPTIONAL
	IDTokenEncryptionAlgValuesSupported       []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenEncryptionEncValuesSupported       []string `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserinfoSigningAlgValuesSupported         []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserinfoEncryptionAlgValuesSupported      []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserinfoEncryptionEncValuesSupported      []string `json:"userinfo_encryption_enc_values_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported    []string `json:"request_object_signing_alg_values_supported,omitempty"`
	DisplayValuesSupported                    []string `json:"display_values_supported,omitempty"`
	ClaimsParameterSupported                  bool     `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported                 bool     `json:"request_parameter_supported,omitempty"`
	RequestURIParameterSupported              bool     `json:"request_uri_parameter_supported,omitempty"`
	RequireRequestURIRegistration             bool     `json:"require_request_uri_registration,omitempty"`
	CodeChallengeMethodsSupported             []string `json:"code_challenge_methods_supported,omitempty"`
	TLSClientCertificateBoundAccessTokens     bool     `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	IntrospectionEndpoint                     string   `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpoint                        string   `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	EndSessionEndpoint                        string   `json:"end_session_endpoint,omitempty"`
	FrontchannelLogoutSupported               bool     `json:"frontchannel_logout_supported,omitempty"`
	FrontchannelLogoutSessionSupported        bool     `json:"frontchannel_logout_session_supported,omitempty"`
	BackchannelLogoutSupported                bool     `json:"backchannel_logout_supported,omitempty"`
	BackchannelLogoutSessionSupported         bool     `json:"backchannel_logout_session_supported,omitempty"`

	// Extensions (not explicitly modeled)
	Extra map[string]interface{} `json:"-"`
}
