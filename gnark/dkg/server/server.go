package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
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

type Server struct {
	Threshold       int
	NumNodes        int
	Nodes           []string
	PublicKeys      map[string]string
	Commitments     map[string][][]byte
	Shares          map[string]map[string]ShareData
	PublicShares    map[string][]byte
	RegisteredNodes map[string]bool
	Ctx             context.Context
	Cancel          context.CancelFunc
	sync.Mutex
}

func NewServer(numNodes, threshold int) (*Server, error) {
	if numNodes <= 0 || threshold <= 0 || threshold > numNodes {
		return nil, fmt.Errorf("invalid parameters: numNodes=%d, threshold=%d", numNodes, threshold)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		Threshold:       threshold,
		NumNodes:        numNodes,
		Nodes:           make([]string, 0, numNodes),
		PublicKeys:      make(map[string]string),
		Commitments:     make(map[string][][]byte),
		Shares:          make(map[string]map[string]ShareData),
		PublicShares:    make(map[string][]byte),
		RegisteredNodes: make(map[string]bool),
		Ctx:             ctx,
		Cancel:          cancel,
	}, nil
}

func (s *Server) health(c echo.Context) error {
	return c.JSON(http.StatusOK, DKGResponse{Status: "success", Message: "Server is up"})
}

func (s *Server) register(c echo.Context) error {
	var req struct {
		PublicKey string `json:"public_key"`
	}
	if err := c.Bind(&req); err != nil {
		log.Errorf("Failed to bind request: %v", err)
		return c.JSON(http.StatusBadRequest, DKGResponse{Status: "error", Message: "Invalid request format"})
	}
	if req.PublicKey == "" {
		return c.JSON(http.StatusBadRequest, DKGResponse{Status: "error", Message: "Public key is required"})
	}
	if _, err := age.ParseX25519Recipient(req.PublicKey); err != nil {
		log.Errorf("Invalid public key: %v", err)
		return c.JSON(http.StatusBadRequest, DKGResponse{Status: "error", Message: "Invalid public key format"})
	}

	s.Lock()
	defer s.Unlock()
	if len(s.RegisteredNodes) >= s.NumNodes {
		return c.JSON(http.StatusForbidden, DKGResponse{Status: "error", Message: "Registration closed"})
	}
	nodeID := len(s.RegisteredNodes) + 1 // Numeric ID: 1, 2, 3, ...
	s.RegisteredNodes[fmt.Sprintf("%d", nodeID)] = true
	s.Nodes = append(s.Nodes, fmt.Sprintf("%d", nodeID))
	s.PublicKeys[fmt.Sprintf("%d", nodeID)] = req.PublicKey
	log.Infof("Registered node %d with public key %s", nodeID, req.PublicKey)
	if len(s.RegisteredNodes) == s.NumNodes {
		s.Cancel() // Signal that registration is complete
		log.Infof("All %d nodes registered, starting DKG", s.NumNodes)
	}
	return c.JSON(http.StatusOK, DKGResponse{
		Status: "success",
		Data: RegisterResponse{
			NodeID:    fmt.Sprintf("%d", nodeID),
			PublicKey: req.PublicKey,
		},
	})
}

func (s *Server) getNodes(c echo.Context) error {
	s.Lock()
	defer s.Unlock()
	if len(s.RegisteredNodes) < s.NumNodes {
		return c.JSON(http.StatusTooEarly, DKGResponse{Status: "error", Message: "Not all nodes registered"})
	}
	return c.JSON(http.StatusOK, DKGResponse{Status: "success", Data: struct {
		Nodes      []string          `json:"nodes"`
		PublicKeys map[string]string `json:"public_keys"`
	}{s.Nodes, s.PublicKeys}})
}

func (s *Server) submitCommitment(c echo.Context) error {
	var req CommitmentData
	if err := c.Bind(&req); err != nil {
		log.Errorf("Failed to bind commitment: %v", err)
		return c.JSON(http.StatusBadRequest, DKGResponse{Status: "error", Message: "Invalid request format"})
	}
	if len(req.Commitment) == 0 {
		return c.JSON(http.StatusBadRequest, DKGResponse{Status: "error", Message: "Commitment data is required"})
	}

	s.Lock()
	defer s.Unlock()
	if s.Ctx.Err() == nil {
		return c.JSON(http.StatusTooEarly, DKGResponse{Status: "error", Message: "Registration not complete"})
	}

	var commits [][]byte
	if err := json.Unmarshal(req.Commitment, &commits); err != nil {
		log.Errorf("Failed to unmarshal commitments: %v", err)
		return c.JSON(http.StatusBadRequest, DKGResponse{Status: "error", Message: "Invalid commitment data"})
	}
	nodeID := c.Request().Header.Get("Node-ID")
	if nodeID == "" {
		return c.JSON(http.StatusBadRequest, DKGResponse{Status: "error", Message: "Node-ID header is required"})
	}
	if _, ok := s.RegisteredNodes[nodeID]; !ok {
		return c.JSON(http.StatusUnauthorized, DKGResponse{Status: "error", Message: "Unregistered node"})
	}
	s.Commitments[nodeID] = commits
	log.Infof("Received commitments from %s", nodeID)
	return c.JSON(http.StatusOK, DKGResponse{Status: "success"})
}

func (s *Server) getCommitments(c echo.Context) error {
	s.Lock()
	defer s.Unlock()
	if len(s.Commitments) < s.NumNodes {
		return c.JSON(http.StatusTooEarly, DKGResponse{Status: "error", Message: "Not all commitments received"})
	}
	serializedCommits := make(map[string][]byte)
	for nodeID, commits := range s.Commitments {
		data, err := json.Marshal(commits)
		if err != nil {
			log.Errorf("Failed to marshal commitments for %s: %v", nodeID, err)
			return c.JSON(http.StatusInternalServerError, DKGResponse{Status: "error", Message: "Internal server error"})
		}
		serializedCommits[nodeID] = data
	}
	return c.JSON(http.StatusOK, DKGResponse{Status: "success", Data: CommitmentsResponse{Commitments: serializedCommits}})
}

func (s *Server) submitShare(c echo.Context) error {
	var req ShareBatchRequest
	if err := c.Bind(&req); err != nil {
		log.Errorf("Failed to bind share batch: %v", err)
		return c.JSON(http.StatusBadRequest, DKGResponse{Status: "error", Message: "Invalid request format"})
	}

	s.Lock()
	defer s.Unlock()
	FromNodeID := c.Request().Header.Get("Node-ID")
	if FromNodeID == "" {
		return c.JSON(http.StatusBadRequest, DKGResponse{Status: "error", Message: "Node-ID header is required"})
	}
	if _, ok := s.RegisteredNodes[FromNodeID]; !ok {
		return c.JSON(http.StatusUnauthorized, DKGResponse{Status: "error", Message: "Unregistered node"})
	}

	if len(req.Shares) == 0 {
		return c.JSON(http.StatusBadRequest, DKGResponse{Status: "error", Message: "Shares map is required"})
	}

	if s.Ctx.Err() == nil {
		return c.JSON(http.StatusTooEarly, DKGResponse{Status: "error", Message: "Registration not complete"})
	}

	for toNodeID, share := range req.Shares {
		if toNodeID == FromNodeID {
			return c.JSON(http.StatusBadRequest, DKGResponse{Status: "error", Message: "Cannot include self in share batch"})
		}
		if _, ok := s.RegisteredNodes[toNodeID]; !ok {
			return c.JSON(http.StatusBadRequest, DKGResponse{Status: "error", Message: fmt.Sprintf("Invalid to_node_id: %s", toNodeID)})
		}
		if len(share.EncryptedShare) == 0 {
			return c.JSON(http.StatusBadRequest, DKGResponse{Status: "error", Message: fmt.Sprintf("Empty share for %s", toNodeID)})
		}
		if s.Shares[FromNodeID] == nil {
			s.Shares[FromNodeID] = make(map[string]ShareData)
		}
		s.Shares[FromNodeID][toNodeID] = share
	}
	log.Infof("Processed batch of %d shares from %s", len(req.Shares), FromNodeID)
	return c.JSON(http.StatusOK, DKGResponse{Status: "success"})
}

func (s *Server) getShares(c echo.Context) error {
	s.Lock()
	defer s.Unlock()
	expectedShareCount := s.NumNodes * (s.NumNodes - 1)
	actualShareCount := 0
	for _, shares := range s.Shares {
		actualShareCount += len(shares)
	}
	if actualShareCount < expectedShareCount {
		return c.JSON(http.StatusTooEarly, DKGResponse{Status: "error", Message: fmt.Sprintf("Not all shares received: got %d, expected %d", actualShareCount, expectedShareCount)})
	}
	return c.JSON(http.StatusOK, DKGResponse{Status: "success", Data: SharesResponse{Shares: s.Shares}})
}

func (s *Server) submitPublicShare(c echo.Context) error {
	var req PublicShareData
	if err := c.Bind(&req); err != nil {
		log.Errorf("Failed to bind public share: %v", err)
		return c.JSON(http.StatusBadRequest, DKGResponse{Status: "error", Message: "Invalid request format"})
	}
	if len(req.PublicShare) == 0 {
		return c.JSON(http.StatusBadRequest, DKGResponse{Status: "error", Message: "Public share data is required"})
	}

	s.Lock()
	defer s.Unlock()
	if s.Ctx.Err() == nil {
		return c.JSON(http.StatusTooEarly, DKGResponse{Status: "error", Message: "Registration not complete"})
	}

	nodeID := c.Request().Header.Get("Node-ID")
	if nodeID == "" {
		return c.JSON(http.StatusBadRequest, DKGResponse{Status: "error", Message: "Node-ID header is required"})
	}
	if _, ok := s.RegisteredNodes[nodeID]; !ok {
		return c.JSON(http.StatusUnauthorized, DKGResponse{Status: "error", Message: "Unregistered node"})
	}
	s.PublicShares[nodeID] = req.PublicShare
	log.Infof("Received public share from %s", nodeID)
	return c.JSON(http.StatusOK, DKGResponse{Status: "success"})
}

func (s *Server) getPublicShares(c echo.Context) error {
	s.Lock()
	defer s.Unlock()
	if len(s.PublicShares) < s.NumNodes {
		return c.JSON(http.StatusTooEarly, DKGResponse{Status: "error", Message: fmt.Sprintf("Not all public shares received: got %d, expected %d", len(s.PublicShares), s.NumNodes)})
	}
	serializedShares := make(map[string][]byte)
	for nodeID, pubKey := range s.PublicShares {
		serializedShares[nodeID] = pubKey
	}
	log.Infof("Returning all %d public shares to client", len(s.PublicShares))
	return c.JSON(http.StatusOK, DKGResponse{Status: "success", Data: PublicSharesResponse{PublicShares: serializedShares}})
}

func main() {
	port := os.Getenv("PORT")
	numNodesStr := os.Getenv("NUM_NODES")
	thresholdStr := os.Getenv("THRESHOLD")

	if port == "" {
		port = "8080"
	}

	if numNodesStr == "" {
		numNodesStr = "5"
	}
	if thresholdStr == "" {
		thresholdStr = "3"
	}

	numNodes, err := strconv.Atoi(numNodesStr)
	if err != nil {
		log.Fatalf("Invalid NUM_NODES: %v", err)
	}
	threshold, err := strconv.Atoi(thresholdStr)
	if err != nil {
		log.Fatalf("Invalid THRESHOLD: %v", err)
	}

	s, err := NewServer(numNodes, threshold)
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	e := echo.New()
	e.Use(middleware.Logger())
	e.HideBanner = true
	e.HidePort = true
	e.Logger.SetLevel(log.INFO)
	e.GET("/health", s.health)
	e.POST("/dkg/register", s.register)
	e.GET("/dkg/nodes", s.getNodes)
	e.POST("/dkg/commitments", s.submitCommitment)
	e.GET("/dkg/commitments", s.getCommitments)
	e.POST("/dkg/shares", s.submitShare)
	e.GET("/dkg/shares", s.getShares)
	e.POST("/dkg/public_shares", s.submitPublicShare)
	e.GET("/dkg/public_shares", s.getPublicShares)

	go func() {
		if err := e.Start(":" + port); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Server failed: %v", err)
		}
	}()
	log.Infof("Server started on :%s with %d nodes and threshold %d", port, numNodes, threshold)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	log.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		log.Errorf("Failed to shutdown server gracefully: %v", err)
	}
	log.Info("Server stopped")
}
