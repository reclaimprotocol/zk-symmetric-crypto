package dkg

// RegisterRequest is the request payload for /dkg/register
type RegisterRequest struct {
	PublicKey string `json:"public_key"`
}

// RegisterResponse is the data payload for /dkg/register
type RegisterResponse struct {
	NodeID    string `json:"node_id"` // UUID
	PublicKey string `json:"public_key"`
}

// NodesResponse is the data payload for /dkg/nodes
type NodesResponse struct {
	Nodes       []string          `json:"nodes"`
	NodeIndices map[string]int    `json:"node_indices"`
	PublicKeys  map[string]string `json:"public_keys"`
	Threshold   int               `json:"threshold"`
}

// CommitmentData is the request payload for /dkg/commitments
type CommitmentData struct {
	Commitment []byte `json:"commitment"`
}

// CommitmentsResponse is the data payload for /dkg/commitments
type CommitmentsResponse struct {
	Commitments map[string][]byte `json:"commitments"`
}

// ShareData is the request/response payload for shares
type ShareData struct {
	EncryptedShare []byte `json:"encrypted_share"`
}

// ShareBatchRequest is the request payload for /dkg/shares
type ShareBatchRequest struct {
	Shares map[string]*ShareData `json:"shares"`
}

// SharesResponse is the data payload for /dkg/shares
type SharesResponse struct {
	Shares map[string]map[string]*ShareData `json:"shares"`
}

// SharesValidationErrors is the data payload for share validation errors
type SharesValidationErrors struct {
	Errors []ValidationError `json:"errors"`
}

// ValidationError represents a single validation error for shares
type ValidationError struct {
	ToNodeID string `json:"to_node_id"`
	Message  string `json:"message"`
}

// PublicShareData is the request payload for /dkg/public_shares
type PublicShareData struct {
	PublicShare []byte `json:"public_share"`
}

// PublicSharesResponse is the data payload for /dkg/public_shares
type PublicSharesResponse struct {
	PublicShares map[string][]byte `json:"public_shares"`
}
