package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"gnark-symmetric-crypto/utils"
	"math/big"
	"net/http"
	"sync"
	"time"

	"filippo.io/age"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

type DKGResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type RegisterResponse struct {
	NodeID    string `json:"node_id"`
	PublicKey string `json:"public_key"`
}

type CommitmentsResponse struct {
	Commitments map[string][]byte `json:"commitments"`
}

type SharesResponse struct {
	Shares map[string]map[string]ShareData `json:"shares"`
}

type PublicSharesResponse struct {
	PublicShares map[string][]byte `json:"public_shares"`
}

type CommitmentData struct {
	Commitment []byte `json:"commitment"`
}

type ShareData struct {
	EncryptedShare []byte `json:"encrypted_share"`
}

type ShareBatchRequest struct {
	FromNodeID string               `json:"from_node_id"`
	Shares     map[string]ShareData `json:"shares"`
}

type PublicShareData struct {
	PublicShare []byte `json:"public_share"`
}

type Client struct {
	NodeID     string
	PublicKeys map[string]age.Recipient
	Identity   *age.X25519Identity
	DKG        *utils.DKG
	httpClient *http.Client
}

func NewClient() *Client {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		panic(fmt.Sprintf("Failed to generate age key pair: %v", err))
	}
	return &Client{
		Identity:   identity,
		PublicKeys: make(map[string]age.Recipient),
		DKG:        nil,
		httpClient: &http.Client{},
	}
}

func (c *Client) post(endpoint string, data interface{}) (DKGResponse, error) {
	var respData DKGResponse
	body, err := json.Marshal(data)
	if err != nil {
		return respData, fmt.Errorf("%s: failed to marshal data for %s: %v", c.NodeID, endpoint, err)
	}
	req, err := http.NewRequest("POST", "http://localhost:8080"+endpoint, bytes.NewBuffer(body))
	if err != nil {
		return respData, fmt.Errorf("%s: failed to create request for %s: %v", c.NodeID, endpoint, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.NodeID != "" {
		req.Header.Set("Node-ID", c.NodeID)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return respData, fmt.Errorf("%s: failed to send request to %s: %v", c.NodeID, endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return respData, fmt.Errorf("%s: unexpected status %d from %s", c.NodeID, resp.StatusCode, endpoint)
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return respData, fmt.Errorf("%s: failed to decode response from %s: %v", c.NodeID, endpoint, err)
	}
	return respData, nil
}

func (c *Client) get(endpoint string, target interface{}) (bool, error) {
	req, err := http.NewRequest("GET", "http://localhost:8080"+endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("%s: failed to create request for %s: %v", c.NodeID, endpoint, err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("%s: failed to send request to %s: %v", c.NodeID, endpoint, err)
	}
	defer resp.Body.Close()
	var respData DKGResponse
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return false, fmt.Errorf("%s: failed to decode response from %s: %v", c.NodeID, endpoint, err)
	}
	if respData.Status != "success" {
		return false, nil
	}
	dataBytes, err := json.Marshal(respData.Data)
	if err != nil {
		return false, fmt.Errorf("%s: failed to marshal response data from %s: %v", c.NodeID, endpoint, err)
	}
	if err := json.Unmarshal(dataBytes, target); err != nil {
		return false, fmt.Errorf("%s: failed to unmarshal response data from %s: %v", c.NodeID, endpoint, err)
	}
	return true, nil
}

func (c *Client) poll(endpoint string, condition func() bool) error {
	timeout := time.After(30 * time.Second) // Increased timeout for 5 nodes
	for {
		select {
		case <-timeout:
			return fmt.Errorf("%s: polling timeout for %s", c.NodeID, endpoint)
		default:
			if condition() {
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func (c *Client) Register() error {
	fmt.Printf("Client registering\n")
	resp, err := c.post("/dkg/register", struct {
		PublicKey string `json:"public_key"`
	}{c.Identity.Recipient().String()})
	if err != nil {
		return fmt.Errorf("failed to register: %v", err)
	}
	if resp.Status != "success" {
		return fmt.Errorf("failed to register: %s", resp.Message)
	}
	var regData RegisterResponse
	dataBytes, _ := json.Marshal(resp.Data)
	if err := json.Unmarshal(dataBytes, &regData); err != nil {
		return fmt.Errorf("failed to unmarshal registration data: %v", err)
	}
	c.NodeID = regData.NodeID
	fmt.Printf("%s: Registered with public key %s\n", c.NodeID, c.Identity.Recipient().String())

	err = c.poll("/dkg/nodes", func() bool {
		type NodesResponse struct {
			Nodes      []string          `json:"nodes"`
			PublicKeys map[string]string `json:"public_keys"`
		}
		var nodesResp NodesResponse
		ok, _ := c.get("/dkg/nodes", &nodesResp)
		if ok {
			c.DKG = utils.NewDKG(len(nodesResp.Nodes)-1, len(nodesResp.Nodes), nodesResp.Nodes, c.NodeID)
			for nodeID, pubKeyStr := range nodesResp.PublicKeys {
				recipient, err := age.ParseX25519Recipient(pubKeyStr)
				if err != nil {
					fmt.Printf("%s: Failed to parse public key for %s: %v\n", c.NodeID, nodeID, err)
					continue
				}
				c.PublicKeys[nodeID] = recipient
			}
			return len(nodesResp.Nodes) == c.DKG.NumNodes && len(c.PublicKeys) == c.DKG.NumNodes
		}
		return false
	})
	if err != nil {
		return fmt.Errorf("%s: failed to sync nodes: %v", c.NodeID, err)
	}
	fmt.Printf("%s: Synced with %d nodes\n", c.NodeID, c.DKG.NumNodes)
	return nil
}

func (c *Client) SubmitCommitments() error {
	c.DKG.GeneratePolynomials()
	commitData, _ := json.Marshal(c.DKG.PublicCommits)
	resp, err := c.post("/dkg/commitments", CommitmentData{Commitment: commitData})
	if err != nil {
		return err
	}
	if resp.Status != "success" {
		return fmt.Errorf("%s: failed to submit commitments: %s", c.NodeID, resp.Message)
	}
	fmt.Printf("%s: Submitted commitments\n", c.NodeID)
	return nil
}

func (c *Client) FetchCommitments() (map[string][]*twistededwards.PointAffine, error) {
	var resp CommitmentsResponse
	err := c.poll("/dkg/commitments", func() bool {
		ok, _ := c.get("/dkg/commitments", &resp)
		return ok && len(resp.Commitments) == c.DKG.NumNodes
	})
	if err != nil {
		return nil, err
	}
	commitMap := make(map[string][]*twistededwards.PointAffine)
	for nodeID, commBytes := range resp.Commitments {
		var commits []*twistededwards.PointAffine
		json.Unmarshal(commBytes, &commits)
		commitMap[nodeID] = commits
	}
	fmt.Printf("%s: Fetched %d commitments\n", c.NodeID, len(commitMap))
	return commitMap, nil
}

func (c *Client) SubmitShares() error {
	c.DKG.GenerateShares()
	shareBatch := ShareBatchRequest{
		FromNodeID: c.NodeID,
		Shares:     make(map[string]ShareData),
	}
	for toNodeID, share := range c.DKG.Shares {
		if toNodeID == c.NodeID {
			continue
		}
		var buf bytes.Buffer
		w, err := age.Encrypt(&buf, c.PublicKeys[toNodeID])
		if err != nil {
			return fmt.Errorf("%s: failed to encrypt share for %s: %v", c.NodeID, toNodeID, err)
		}
		_, err = w.Write([]byte(share.String()))
		if err != nil {
			return fmt.Errorf("%s: failed to write encrypted share for %s: %v", c.NodeID, toNodeID, err)
		}
		w.Close()
		shareBatch.Shares[toNodeID] = ShareData{EncryptedShare: buf.Bytes()}
	}
	resp, err := c.post("/dkg/shares", shareBatch)
	if err != nil {
		return err
	}
	if resp.Status != "success" {
		return fmt.Errorf("%s: failed to submit share batch: %s", c.NodeID, resp.Message)
	}
	fmt.Printf("%s: Submitted batch of %d shares\n", c.NodeID, len(shareBatch.Shares))
	return nil
}

func (c *Client) FetchShares() error {
	var resp SharesResponse
	err := c.poll("/dkg/shares", func() bool {
		ok, _ := c.get("/dkg/shares", &resp)
		if ok {
			c.DKG.ReceivedShares = make(map[string]*big.Int)
			for fromNodeID, shares := range resp.Shares {
				if share, ok := shares[c.NodeID]; ok {
					r, err := age.Decrypt(bytes.NewReader(share.EncryptedShare), c.Identity)
					if err != nil {
						fmt.Printf("%s: Failed to decrypt share from %s: %v\n", c.NodeID, fromNodeID, err)
						continue
					}
					var decrypted bytes.Buffer
					_, err = decrypted.ReadFrom(r)
					if err != nil {
						fmt.Printf("%s: Failed to read decrypted share from %s: %v\n", c.NodeID, fromNodeID, err)
						continue
					}
					secret, _ := new(big.Int).SetString(decrypted.String(), 10)
					c.DKG.ReceivedShares[fromNodeID] = secret
					// fmt.Printf("%s: Received share from %s: %s\n", c.NodeID, fromNodeID, secret.String())
				}
			}
			return len(c.DKG.ReceivedShares) == c.DKG.NumNodes-1
		}
		return false
	})
	if err != nil {
		return err
	}
	fmt.Printf("%s: Fetched %d shares\n", c.NodeID, len(c.DKG.ReceivedShares))
	return nil
}

func (c *Client) SubmitPublicShare() error {
	resp, err := c.post("/dkg/public_shares", PublicShareData{PublicShare: c.DKG.PublicKey.Marshal()})
	if err != nil {
		return err
	}
	if resp.Status != "success" {
		return fmt.Errorf("%s: failed to submit public share: %s", c.NodeID, resp.Message)
	}
	// fmt.Printf("%s: Submitted public share: X=%s, Y=%s\n", c.NodeID, c.DKG.PublicKey.X.String(), c.DKG.PublicKey.Y.String())
	return nil
}

func (c *Client) FetchPublicShares() (map[string]*twistededwards.PointAffine, error) {
	var resp PublicSharesResponse
	err := c.poll("/dkg/public_shares", func() bool {
		ok, _ := c.get("/dkg/public_shares", &resp)
		return ok && len(resp.PublicShares) == c.DKG.NumNodes
	})
	if err != nil {
		return nil, err
	}
	publicShares := make(map[string]*twistededwards.PointAffine)
	for nodeID, pubBytes := range resp.PublicShares {
		var pubKey twistededwards.PointAffine
		if err := pubKey.Unmarshal(pubBytes); err != nil {
			fmt.Printf("%s: Failed to unmarshal public share for %s: %v\n", c.NodeID, nodeID, err)
			continue
		}
		publicShares[nodeID] = &pubKey
		// fmt.Printf("%s: Fetched public share for %s: X=%s, Y=%s\n", c.NodeID, nodeID, pubKey.X.String(), pubKey.Y.String())
	}
	if len(publicShares) != c.DKG.NumNodes {
		return nil, fmt.Errorf("%s: expected %d public shares, got %d", c.NodeID, c.DKG.NumNodes, len(publicShares))
	}
	fmt.Printf("%s: Fetched %d public shares total\n", c.NodeID, len(publicShares))
	return publicShares, nil
}

func (c *Client) Run() {
	if err := c.Register(); err != nil {
		fmt.Printf("%s: Failed to register: %v\n", c.NodeID, err)
		return
	}
	if err := c.SubmitCommitments(); err != nil {
		fmt.Printf("%s: Failed to submit commitments: %v\n", c.NodeID, err)
		return
	}
	commitments, err := c.FetchCommitments()
	if err != nil {
		fmt.Printf("%s: Failed to fetch commitments: %v\n", c.NodeID, err)
		return
	}
	if err := c.SubmitShares(); err != nil {
		fmt.Printf("%s: Failed to submit shares: %v\n", c.NodeID, err)
		return
	}
	if err := c.FetchShares(); err != nil {
		fmt.Printf("%s: Failed to fetch shares: %v\n", c.NodeID, err)
		return
	}
	if err := c.DKG.VerifyShares(commitments, c.NodeID); err != nil {
		fmt.Printf("%s: Failed to verify shares: %v\n", c.NodeID, err)
		return
	}
	c.DKG.ComputeFinalKeys()
	// fmt.Printf("%s: Computed final public key: X=%s, Y=%s\n", c.NodeID, c.DKG.PublicKey.X.String(), c.DKG.PublicKey.Y.String())
	if err := c.SubmitPublicShare(); err != nil {
		fmt.Printf("%s: Failed to submit public share: %v\n", c.NodeID, err)
		return
	}
	publicShares, err := c.FetchPublicShares()
	if err != nil {
		fmt.Printf("%s: Failed to fetch public shares: %v\n", c.NodeID, err)
		return
	}
	masterPubKey := c.DKG.ReconstructMasterPublicKey(publicShares)
	fmt.Printf("%s: Master Public Key - X=%s, Y=%s\n", c.NodeID, masterPubKey.X.String(), masterPubKey.Y.String())
}

func waitForServer() {
	client := &http.Client{Timeout: 1 * time.Second}
	for {
		resp, err := client.Get("http://localhost:8080/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			fmt.Println("Server is ready")
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func main() {
	numNodes := 3
	waitForServer()
	var wg sync.WaitGroup
	for i := 0; i < numNodes; i++ {
		wg.Add(1)
		client := NewClient()
		go func(c *Client) {
			defer wg.Done()
			c.Run()
		}(client)
	}
	wg.Wait()
}
