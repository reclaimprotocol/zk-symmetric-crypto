package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	types "gnark-symmetric-crypto/dkg"
	"gnark-symmetric-crypto/utils"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"filippo.io/age"
)

// Import shared types
type (
	RegisterRequest      = types.RegisterRequest
	RegisterResponse     = types.RegisterResponse
	NodesResponse        = types.NodesResponse
	CommitmentData       = types.CommitmentData
	CommitmentsResponse  = types.CommitmentsResponse
	ShareData            = types.ShareData
	ShareBatchRequest    = types.ShareBatchRequest
	SharesResponse       = types.SharesResponse
	PublicShareData      = types.PublicShareData
	PublicSharesResponse = types.PublicSharesResponse
)

var DkgHost = "http://localhost:8080"

var nodeID string

// DKGResponse is a generic response type with a typed Data field
type DKGResponse[T any] struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Data    T      `json:"data,omitempty"`
}

type Client struct {
	NodeID           string
	NodeIndex        int
	PublicKeys       map[string]age.Recipient // UUID -> PublicKey
	NodeIndices      map[string]int           // UUID -> NodeIndex
	IndexToUUID      map[int]string           // NodeIndex -> UUID
	Identity         *age.X25519Identity      // Pointer
	DKG              *utils.DKG               // Pointer
	httpClient       *http.Client             // Pointer
	LocalCommitments [][]byte                 // Value (immutable after set)
}

func NewClient() *Client {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		panic(fmt.Sprintf("Failed to generate age key pair: %v", err))
	}
	return &Client{
		Identity:         identity,
		PublicKeys:       make(map[string]age.Recipient),
		NodeIndices:      make(map[string]int),
		IndexToUUID:      make(map[int]string),
		DKG:              nil,
		httpClient:       &http.Client{},
		LocalCommitments: nil,
	}
}

// post returns a pointer to DKGResponse
func post[TReq any, TResp any](c *Client, endpoint string, data *TReq) (*DKGResponse[TResp], error) {
	respData := &DKGResponse[TResp]{}
	body, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data for %s: %v", c.NodeID, endpoint, err)
	}
	req, err := http.NewRequest("POST", DkgHost+endpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create request for %s: %v", c.NodeID, endpoint, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.NodeID != "" {
		req.Header.Set("Node-ID", c.NodeID)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to send request to %s: %v", c.NodeID, endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: unexpected status %d from %s", c.NodeID, resp.StatusCode, endpoint)
	}
	if err := json.NewDecoder(resp.Body).Decode(respData); err != nil {
		return nil, fmt.Errorf("%s: failed to decode response from %s: %v", c.NodeID, endpoint, err)
	}
	return respData, nil
}

// get returns a pointer to DKGResponse
func get[TResp any](c *Client, endpoint string) (*DKGResponse[TResp], error) {
	respData := &DKGResponse[TResp]{}
	req, err := http.NewRequest("GET", DkgHost+endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create request for %s: %v", c.NodeID, endpoint, err)
	}
	if c.NodeID != "" {
		req.Header.Set("Node-ID", c.NodeID)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to send request to %s: %v", c.NodeID, endpoint, err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(respData); err != nil {
		return nil, fmt.Errorf("%s: failed to decode response from %s: %v", c.NodeID, endpoint, err)
	}
	return respData, nil
}

// poll uses pointer to DKGResponse
func poll[T any](c *Client, endpoint string, condition func(*DKGResponse[T]) bool) error {
	timeout := time.After(30 * time.Minute)
	for {
		select {
		case <-timeout:
			return fmt.Errorf("%s: polling timeout for %s", c.NodeID, endpoint)
		default:
			resp, err := get[T](c, endpoint)
			if err != nil {
				fmt.Printf("%s: failed to poll %s: %v\n", c.NodeID, endpoint, err)
				time.Sleep(500 * time.Millisecond)
				continue
			}
			if condition(resp) {
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func (c *Client) Register() error {
	fmt.Printf("Client registering\n")
	req := &RegisterRequest{PublicKey: c.Identity.Recipient().String()}
	resp, err := post[RegisterRequest, RegisterResponse](c, "/dkg/register", req)
	if err != nil {
		return fmt.Errorf("failed to register: %v", err)
	}
	if resp.Status != "success" {
		return fmt.Errorf("failed to register: %s", resp.Message)
	}
	fmt.Printf("%s: Registered with public key %s\n", c.NodeID, c.Identity.Recipient().String())

	err = poll(c, "/dkg/nodes", func(resp *DKGResponse[NodesResponse]) bool {
		if resp.Status != "success" {
			return false
		}
		c.NodeIndex = resp.Data.NodeIndices[c.NodeID]
		c.NodeIndices = resp.Data.NodeIndices
		for uuid, index := range resp.Data.NodeIndices {
			c.IndexToUUID[index] = uuid
		}
		nodes := make([]string, len(resp.Data.Nodes))
		for i, uuid := range resp.Data.Nodes {
			nodes[i] = strconv.Itoa(resp.Data.NodeIndices[uuid])
		}
		// Use server-provided Threshold
		c.DKG = utils.NewDKG(resp.Data.Threshold, len(resp.Data.Nodes), nodes, strconv.Itoa(c.NodeIndex))
		for nodeID, pubKeyStr := range resp.Data.PublicKeys {
			recipient, err := age.ParseX25519Recipient(pubKeyStr)
			if err != nil {
				fmt.Printf("%s: Failed to parse public key for %s: %v\n", c.NodeID, nodeID, err)
				continue
			}
			c.PublicKeys[nodeID] = recipient
		}
		return len(resp.Data.Nodes) == c.DKG.NumNodes && len(c.PublicKeys) == c.DKG.NumNodes && c.NodeIndex > 0
	})
	if err != nil {
		return fmt.Errorf("%s: failed to sync nodes: %v", c.NodeID, err)
	}
	fmt.Printf("%s: Synced with %d nodes, index %d, threshold %d\n", c.NodeID, c.DKG.NumNodes, c.NodeIndex, c.DKG.Threshold)
	return nil
}

func (c *Client) SubmitCommitments() error {
	c.DKG.GeneratePolynomials()
	commitData, err := c.DKG.MarshalCommitments()
	if err != nil {
		return fmt.Errorf("%s: failed to marshal commitments: %v", c.NodeID, err)
	}
	var localCommits [][]byte
	if err := json.Unmarshal(commitData, &localCommits); err != nil {
		return fmt.Errorf("%s: failed to unmarshal local commitments: %v", c.NodeID, err)
	}
	c.LocalCommitments = localCommits
	req := &CommitmentData{Commitment: commitData}
	resp, err := post[CommitmentData, struct{}](c, "/dkg/commitments", req)
	if err != nil {
		return err
	}
	if resp.Status != "success" {
		return fmt.Errorf("%s: failed to submit commitments: %s", c.NodeID, resp.Message)
	}
	fmt.Printf("%s: Submitted commitments\n", c.NodeID)
	return nil
}

func (c *Client) FetchCommitments() (map[string][][]byte, error) {
	err := poll(c, "/dkg/commitments", func(resp *DKGResponse[CommitmentsResponse]) bool {
		return resp.Status == "success" && len(resp.Data.Commitments) == c.DKG.NumNodes
	})
	if err != nil {
		return nil, err
	}
	resp, err := get[CommitmentsResponse](c, "/dkg/commitments")
	if err != nil {
		return nil, fmt.Errorf("%s: failed to fetch commitments: %v", c.NodeID, err)
	}
	commitMap := make(map[string][][]byte)
	for nodeID, commBytes := range resp.Data.Commitments {
		var commits [][]byte
		if err := json.Unmarshal(commBytes, &commits); err != nil {
			return nil, fmt.Errorf("%s: failed to unmarshal commitments for node %s: %v", c.NodeID, nodeID, err)
		}
		indexStr := strconv.Itoa(c.NodeIndices[nodeID])
		commitMap[indexStr] = commits
	}
	ownIndexStr := strconv.Itoa(c.NodeIndex)
	serverCommits, ok := commitMap[ownIndexStr]
	if !ok {
		return nil, fmt.Errorf("%s: server did not return our commitment for index %s", c.NodeID, ownIndexStr)
	}
	if len(serverCommits) != len(c.LocalCommitments) {
		return nil, fmt.Errorf("%s: commitment length mismatch: local %d, server %d", c.NodeID, len(c.LocalCommitments), len(serverCommits))
	}
	for i, local := range c.LocalCommitments {
		if !bytes.Equal(local, serverCommits[i]) {
			return nil, fmt.Errorf("%s: commitment mismatch at position %d: local %x, server %x", c.NodeID, i, local, serverCommits[i])
		}
	}
	fmt.Printf("%s: Fetched %d commitments (own commitment verified)\n", c.NodeID, len(commitMap))
	return commitMap, nil
}

func (c *Client) SubmitShares() error {
	c.DKG.GenerateShares()
	shareBatch := &ShareBatchRequest{
		Shares: make(map[string]*ShareData),
	}
	for toNodeIndexStr, share := range c.DKG.Shares {
		if toNodeIndexStr == strconv.Itoa(c.NodeIndex) {
			continue
		}
		uuidNodeID := c.findUUIDByIndex(toNodeIndexStr)
		if uuidNodeID == "" {
			return fmt.Errorf("%s: no UUID found for index %s", c.NodeID, toNodeIndexStr)
		}
		var buf bytes.Buffer
		w, err := age.Encrypt(&buf, c.PublicKeys[uuidNodeID])
		if err != nil {
			return fmt.Errorf("%s: failed to encrypt share for index %s (UUID %s): %v", c.NodeID, toNodeIndexStr, uuidNodeID, err)
		}
		if _, err = w.Write([]byte(share.String())); err != nil {
			_ = w.Close()
			return fmt.Errorf("%s: failed to write encrypted share for index %s (UUID %s): %v", c.NodeID, toNodeIndexStr, uuidNodeID, err)
		}
		if err = w.Close(); err != nil {
			return fmt.Errorf("%s: failed to close encrypt writer for index %s (UUID %s): %v", c.NodeID, toNodeIndexStr, uuidNodeID, err)
		}
		shareData := &ShareData{}              // Allocate pointer first
		shareData.EncryptedShare = buf.Bytes() // Assign field
		shareBatch.Shares[uuidNodeID] = shareData
	}
	resp, err := post[ShareBatchRequest, struct{}](c, "/dkg/shares", shareBatch)
	if err != nil {
		return err
	}
	if resp.Status != "success" {
		return fmt.Errorf("%s: failed to submit share batch: %s", c.NodeID, resp.Message)
	}
	fmt.Printf("%s: Submitted batch of %d shares\n", c.NodeID, len(shareBatch.Shares))
	return nil
}

func (c *Client) findUUIDByIndex(indexStr string) string {
	index, err := strconv.Atoi(indexStr)
	if err != nil {
		fmt.Printf("%s: failed to parse index %s: %v\n", c.NodeID, indexStr, err)
		return ""
	}
	uuid, ok := c.IndexToUUID[index]
	if !ok {
		fmt.Printf("%s: no UUID mapped for index %d\n", c.NodeID, index)
		return ""
	}
	return uuid
}

func (c *Client) FetchShares() error {
	err := poll(c, "/dkg/shares", func(resp *DKGResponse[SharesResponse]) bool {
		if resp.Status != "success" {
			return false
		}
		c.DKG.ReceivedShares = make(map[string]*big.Int)
		for fromNodeID, shares := range resp.Data.Shares {
			if share, ok := shares[c.NodeID]; ok {
				r, err := age.Decrypt(bytes.NewReader(share.EncryptedShare), c.Identity)
				if err != nil {
					fmt.Printf("%s: failed to decrypt share from %s: %v\n", c.NodeID, fromNodeID, err)
					continue
				}
				var decrypted bytes.Buffer
				_, err = decrypted.ReadFrom(r)
				if err != nil {
					fmt.Printf("%s: failed to read decrypted share from %s: %v\n", c.NodeID, fromNodeID, err)
					continue
				}
				secret, ok := new(big.Int).SetString(decrypted.String(), 10)
				if !ok {
					fmt.Printf("%s: failed to parse decrypted share from %s: %s\n", c.NodeID, fromNodeID, decrypted.String())
					continue
				}
				fromIndex := strconv.Itoa(c.NodeIndices[fromNodeID])
				c.DKG.ReceivedShares[fromIndex] = secret
			}
		}
		return len(c.DKG.ReceivedShares) == c.DKG.NumNodes-1
	})
	if err != nil {
		return err
	}
	fmt.Printf("%s: Fetched %d shares\n", c.NodeID, len(c.DKG.ReceivedShares))
	return nil
}

func (c *Client) SubmitPublicShare() error {
	req := &PublicShareData{PublicShare: c.DKG.PublicKey.Marshal()}
	resp, err := post[PublicShareData, struct{}](c, "/dkg/public_shares", req)
	if err != nil {
		return err
	}
	if resp.Status != "success" {
		return fmt.Errorf("%s: failed to submit public share: %s", c.NodeID, resp.Message)
	}
	return nil
}

func (c *Client) FetchPublicShares() (map[int][]byte, error) {
	err := poll(c, "/dkg/public_shares", func(resp *DKGResponse[PublicSharesResponse]) bool {
		return resp.Status == "success" && len(resp.Data.PublicShares) == c.DKG.NumNodes
	})
	if err != nil {
		return nil, err
	}
	resp, err := get[PublicSharesResponse](c, "/dkg/public_shares")
	if err != nil {
		return nil, fmt.Errorf("%s: failed to fetch public shares: %v", c.NodeID, err)
	}
	publicShares := make(map[int][]byte)
	for nodeID, pubBytes := range resp.Data.PublicShares {
		index, ok := c.NodeIndices[nodeID]
		if !ok {
			return nil, fmt.Errorf("%s: missing NodeIndex for node %s", c.NodeID, nodeID)
		}
		publicShares[index] = pubBytes
	}
	if len(publicShares) != c.DKG.NumNodes {
		return nil, fmt.Errorf("%s: expected %d public shares, got %d", c.NodeID, c.DKG.NumNodes, len(publicShares))
	}
	fmt.Printf("%s: Fetched %d public shares total\n", c.NodeID, len(publicShares))
	return publicShares, nil
}

// type ClientResult struct {
// 	NodeID       string
// 	Secret       *big.Int
// 	PublicKey    *twistededwards.PointAffine
// 	MasterPubKey *twistededwards.PointAffine
// }

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
	if err := c.DKG.VerifyShares(commitments, strconv.Itoa(c.NodeIndex)); err != nil {
		fmt.Printf("%s: Failed to verify shares: %v\n", c.NodeID, err)
		return
	}
	c.DKG.ComputeFinalKeys()
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

	fmt.Printf("Node index: %d, Share secret key: %s Public key: %s\n", c.NodeIndex, c.DKG.Secret.String(), base64.StdEncoding.EncodeToString(c.DKG.PublicKey.Marshal()))
	// Send result to channel
	/*results <- &ClientResult{
		NodeID:       c.NodeID,
		Secret:       new(big.Int).Set(c.DKG.Secret),
		PublicKey:    c.DKG.PublicKey,
		MasterPubKey: masterPubKey,
	}*/
}

func waitForServer() {
	client := &http.Client{Timeout: 1 * time.Second}
	for {
		resp, err := client.Get(DkgHost + "/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			if err := resp.Body.Close(); err != nil {
				fmt.Printf("Failed to close health check response body: %v\n", err)
			}
			fmt.Println("Server is ready")
			break
		}
		if resp != nil {
			if err := resp.Body.Close(); err != nil {
				fmt.Printf("Failed to close health check response body: %v\n", err)
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func main() {

	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s URL Node-ID\n", os.Args[0])
		return
	}

	DkgHost = os.Args[1]
	nodeID = os.Args[2]

	numNodes := 1
	waitForServer()
	var wg sync.WaitGroup
	// resultsChan := make(chan *ClientResult, numNodes)
	clients := make([]*Client, numNodes)

	for i := 0; i < numNodes; i++ {
		wg.Add(1)
		clients[i] = NewClient()
		clients[i].NodeID = nodeID
		go func(c *Client) {
			defer wg.Done()
			c.Run()
		}(clients[i])
	}
	wg.Wait()

	/*// Process results
	secretShares := make(map[int]*big.Int)
	var masterPubKey *twistededwards.PointAffine
	for result := range resultsChan {
		index := clients[0].NodeIndices[result.NodeID]
		secretShares[index] = result.Secret
		if masterPubKey == nil {
			masterPubKey = result.MasterPubKey
		} else if !masterPubKey.Equal(result.MasterPubKey) {
			fmt.Printf("Mismatch in master public keys: %s vs %s\n", masterPubKey.X.String(), result.MasterPubKey.X.String())
		}
	}
	var curve = twistededwards.GetEdwardsCurve()
	dkg := clients[0].DKG
	masterPrivateKey := dkg.ReconstructPrivateKey(secretShares)
	derivedPubKey := new(twistededwards.PointAffine)
	derivedPubKey.ScalarMultiplication(&curve.Base, masterPrivateKey)

	fmt.Printf("Reconstructed Master Private Key (with %d shares): %s\n", dkg.Threshold, masterPrivateKey.String())
	fmt.Printf("Derived Master Public Key - X=%s, Y=%s\n", derivedPubKey.X.String(), derivedPubKey.Y.String())
	fmt.Printf("Original Master Public Key - X=%s, Y=%s\n", masterPubKey.X.String(), masterPubKey.Y.String())

	if derivedPubKey.Equal(masterPubKey) {
		fmt.Println("Verification successful: Reconstructed private key matches master public key!")
	} else {
		fmt.Println("Verification failed: Reconstructed private key does not match master public key.")
	}*/
}
