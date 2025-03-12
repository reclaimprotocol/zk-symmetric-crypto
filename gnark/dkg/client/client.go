package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"gnark-symmetric-crypto/utils"
	"math/big"
	"net/http"
	"strconv"
	"sync"
	"time"

	"filippo.io/age"
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
	Shares map[string]ShareData `json:"shares"`
}

type PublicShareData struct {
	PublicShare []byte `json:"public_share"`
}

type Client struct {
	NodeID           string
	NodeIndex        int
	PublicKeys       map[string]age.Recipient // UUID -> PublicKey
	NodeIndices      map[string]int           // UUID -> NodeIndex
	IndexToUUID      map[int]string           // NodeIndex -> UUID (reverse map)
	Identity         *age.X25519Identity
	DKG              *utils.DKG
	httpClient       *http.Client
	LocalCommitments [][]byte // Store our own commitments for verification
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
	if err = json.Unmarshal(dataBytes, target); err != nil {
		return false, fmt.Errorf("%s: failed to unmarshal response data from %s: %v", c.NodeID, endpoint, err)
	}
	return true, nil
}

func (c *Client) poll(endpoint string, condition func() bool) error {
	timeout := time.After(30 * time.Second)
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
	dataBytes, err := json.Marshal(resp.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal register response: %v", err)
	}
	if err = json.Unmarshal(dataBytes, &regData); err != nil {
		return fmt.Errorf("failed to unmarshal registration data: %v", err)
	}
	c.NodeID = regData.NodeID
	fmt.Printf("%s: Registered with public key %s\n", c.NodeID, c.Identity.Recipient().String())

	err = c.poll("/dkg/nodes", func() bool {
		type NodesResponse struct {
			Nodes       []string          `json:"nodes"`
			NodeIndices map[string]int    `json:"node_indices"`
			PublicKeys  map[string]string `json:"public_keys"`
		}
		var nodesResp NodesResponse
		ok, err := c.get("/dkg/nodes", &nodesResp)
		if err != nil {
			fmt.Printf("%s: failed to get nodes: %v\n", c.NodeID, err)
			return false
		}
		if ok {
			c.NodeIndex = nodesResp.NodeIndices[c.NodeID]
			c.NodeIndices = nodesResp.NodeIndices
			// Populate reverse map
			for uuid, index := range nodesResp.NodeIndices {
				c.IndexToUUID[index] = uuid
			}
			nodes := make([]string, len(nodesResp.Nodes))
			for i, uuid := range nodesResp.Nodes {
				nodes[i] = strconv.Itoa(nodesResp.NodeIndices[uuid])
			}
			c.DKG = utils.NewDKG(len(nodesResp.Nodes)-1, len(nodesResp.Nodes), nodes, strconv.Itoa(c.NodeIndex))
			for nodeID, pubKeyStr := range nodesResp.PublicKeys {
				recipient, err := age.ParseX25519Recipient(pubKeyStr)
				if err != nil {
					fmt.Printf("%s: Failed to parse public key for %s: %v\n", c.NodeID, nodeID, err)
					continue
				}
				c.PublicKeys[nodeID] = recipient
			}
			return len(nodesResp.Nodes) == c.DKG.NumNodes && len(c.PublicKeys) == c.DKG.NumNodes && c.NodeIndex > 0
		}
		return false
	})
	if err != nil {
		return fmt.Errorf("%s: failed to sync nodes: %v", c.NodeID, err)
	}
	fmt.Printf("%s: Synced with %d nodes, index %d\n", c.NodeID, c.DKG.NumNodes, c.NodeIndex)
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

func (c *Client) FetchCommitments() (map[string][][]byte, error) {
	var resp CommitmentsResponse
	err := c.poll("/dkg/commitments", func() bool {
		ok, err := c.get("/dkg/commitments", &resp)
		if err != nil {
			fmt.Printf("%s: failed to poll commitments: %v\n", c.NodeID, err)
			return false
		}
		return ok && len(resp.Commitments) == c.DKG.NumNodes
	})
	if err != nil {
		return nil, err
	}
	commitMap := make(map[string][][]byte)
	for nodeID, commBytes := range resp.Commitments {
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
	shareBatch := ShareBatchRequest{
		Shares: make(map[string]ShareData),
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
			w.Close() // Ensure close even on error
			return fmt.Errorf("%s: failed to write encrypted share for index %s (UUID %s): %v", c.NodeID, toNodeIndexStr, uuidNodeID, err)
		}
		if err = w.Close(); err != nil {
			return fmt.Errorf("%s: failed to close encrypt writer for index %s (UUID %s): %v", c.NodeID, toNodeIndexStr, uuidNodeID, err)
		}
		shareBatch.Shares[uuidNodeID] = ShareData{EncryptedShare: buf.Bytes()}
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
	var resp SharesResponse
	err := c.poll("/dkg/shares", func() bool {
		ok, err := c.get("/dkg/shares", &resp)
		if err != nil {
			fmt.Printf("%s: failed to poll shares: %v\n", c.NodeID, err)
			return false
		}
		if ok {
			c.DKG.ReceivedShares = make(map[string]*big.Int)
			for fromNodeID, shares := range resp.Shares {
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
	return nil
}

func (c *Client) FetchPublicShares() (map[int][]byte, error) {
	var resp PublicSharesResponse
	err := c.poll("/dkg/public_shares", func() bool {
		ok, err := c.get("/dkg/public_shares", &resp)
		if err != nil {
			fmt.Printf("%s: failed to poll public shares: %v\n", c.NodeID, err)
			return false
		}
		return ok && len(resp.PublicShares) == c.DKG.NumNodes
	})
	if err != nil {
		return nil, err
	}
	publicShares := make(map[int][]byte)
	for nodeID, pubBytes := range resp.PublicShares {
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
}

func waitForServer() {
	client := &http.Client{Timeout: 1 * time.Second}
	for {
		resp, err := client.Get("http://localhost:8080/health")
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
	numNodes := 5
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
