package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	types "gnark-symmetric-crypto/dkg"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
)

// Import shared types
type (
	RegisterRequest        = types.RegisterRequest
	RegisterResponse       = types.RegisterResponse
	NodesResponse          = types.NodesResponse
	CommitmentData         = types.CommitmentData
	CommitmentsResponse    = types.CommitmentsResponse
	ShareData              = types.ShareData
	ShareBatchRequest      = types.ShareBatchRequest
	SharesResponse         = types.SharesResponse
	SharesValidationErrors = types.SharesValidationErrors
	ValidationError        = types.ValidationError
	PublicShareData        = types.PublicShareData
	PublicSharesResponse   = types.PublicSharesResponse
)

var nodeIds = map[string]bool{}

// BaseResponse holds common fields for all responses
type BaseResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// RegisterResponseFull is the full response for /dkg/register
type RegisterResponseFull struct {
	BaseResponse
	Data *RegisterResponse `json:"data"`
}

// NodesResponseFull is the full response for /dkg/nodes
type NodesResponseFull struct {
	BaseResponse
	Data *NodesResponse `json:"data"`
}

// CommitmentsResponseFull is the full response for /dkg/commitments (POST and GET)
type CommitmentsResponseFull struct {
	BaseResponse
	Data *CommitmentsResponse `json:"data,omitempty"`
}

// SharesResponseFull is the full response for /dkg/shares (POST and GET)
type SharesResponseFull struct {
	BaseResponse
	Data *SharesResponse `json:"data,omitempty"`
}

// SharesValidationErrorResponse is the error response for /dkg/shares validation failures
type SharesValidationErrorResponse struct {
	BaseResponse
	Data *SharesValidationErrors `json:"data"`
}

// PublicSharesResponseFull is the full response for /dkg/public_shares (POST and GET)
type PublicSharesResponseFull struct {
	BaseResponse
	Data *PublicSharesResponse `json:"data,omitempty"`
}

// HealthResponse is the full response for /health
type HealthResponse struct {
	BaseResponse
}

type Server struct {
	Threshold       int
	NumNodes        int
	Nodes           []string
	NodeIndices     map[string]int
	PublicKeys      map[string]string
	Commitments     map[string][][]byte
	Shares          map[string]map[string]*ShareData
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
		NodeIndices:     make(map[string]int),
		PublicKeys:      make(map[string]string),
		Commitments:     make(map[string][][]byte),
		Shares:          make(map[string]map[string]*ShareData),
		PublicShares:    make(map[string][]byte),
		RegisteredNodes: make(map[string]bool),
		Ctx:             ctx,
		Cancel:          cancel,
	}, nil
}

func ensureRegistrationComplete(s *Server) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			s.Lock()
			if s.Ctx.Err() == nil {
				s.Unlock()
				return c.JSON(http.StatusTooEarly, &BaseResponse{Status: "error", Message: "Registration not complete"})
			}
			s.Unlock()
			return next(c)
		}
	}
}

func (s *Server) health(c echo.Context) error {
	return c.JSON(http.StatusOK, &HealthResponse{BaseResponse: BaseResponse{Status: "success", Message: "Server is up"}})
}

func (s *Server) register(c echo.Context) error {
	req := &RegisterRequest{} // Use named struct from types
	if err := c.Bind(req); err != nil {
		log.Errorf("Failed to bind request: %v", err)
		return c.JSON(http.StatusBadRequest, &BaseResponse{Status: "error", Message: "Invalid request format"})
	}

	nodeID := c.Request().Header.Get("Node-ID")
	if nodeID == "" {
		return c.JSON(http.StatusBadRequest, &BaseResponse{Status: "error", Message: "Node-ID header is required"})
	}

	if _, ok := nodeIds[nodeID]; !ok {
		return c.JSON(http.StatusBadRequest, &BaseResponse{Status: "error", Message: "Invalid Node-ID"})
	}

	if nodeIds[nodeID] {
		return c.JSON(http.StatusBadRequest, &BaseResponse{Status: "error", Message: "Node-ID already registered"})
	} else {
		nodeIds[nodeID] = true
	}

	if req.PublicKey == "" {
		return c.JSON(http.StatusBadRequest, &BaseResponse{Status: "error", Message: "Public key is required"})
	}
	if _, err := age.ParseX25519Recipient(req.PublicKey); err != nil {
		log.Errorf("Invalid public key: %v", err)
		return c.JSON(http.StatusBadRequest, &BaseResponse{Status: "error", Message: "Invalid public key format"})
	}

	s.Lock()
	defer s.Unlock()
	if len(s.RegisteredNodes) >= s.NumNodes {
		return c.JSON(http.StatusForbidden, &BaseResponse{Status: "error", Message: "Registration closed"})
	}

	s.RegisteredNodes[nodeID] = true
	s.Nodes = append(s.Nodes, nodeID)
	s.PublicKeys[nodeID] = req.PublicKey
	log.Infof("Registered node %s with public key %s", nodeID, req.PublicKey)

	if len(s.RegisteredNodes) == s.NumNodes {
		for i, nid := range s.Nodes {
			s.NodeIndices[nid] = i + 1 // 1-based indexing
		}
		s.Cancel()
		log.Infof("All %d nodes registered, starting DKG", s.NumNodes)
	}

	return c.JSON(http.StatusOK, &RegisterResponseFull{
		BaseResponse: BaseResponse{Status: "success"},
		Data:         &RegisterResponse{NodeID: nodeID, PublicKey: req.PublicKey},
	})
}

func (s *Server) getNodes(c echo.Context) error {
	s.Lock()
	defer s.Unlock()
	if len(s.RegisteredNodes) < s.NumNodes {
		return c.JSON(http.StatusTooEarly, &BaseResponse{Status: "error", Message: "Not all nodes registered"})
	}
	return c.JSON(http.StatusOK, &NodesResponseFull{
		BaseResponse: BaseResponse{Status: "success"},
		Data: &NodesResponse{
			Nodes:       s.Nodes,
			NodeIndices: s.NodeIndices,
			PublicKeys:  s.PublicKeys,
			Threshold:   s.Threshold,
		},
	})
}

func (s *Server) submitCommitment(c echo.Context) error {
	req := &CommitmentData{}
	if err := c.Bind(req); err != nil {
		log.Errorf("Failed to bind commitment: %v", err)
		return c.JSON(http.StatusBadRequest, &BaseResponse{Status: "error", Message: "Invalid request format"})
	}
	if len(req.Commitment) == 0 {
		return c.JSON(http.StatusBadRequest, &BaseResponse{Status: "error", Message: "Commitment data is required"})
	}

	s.Lock()
	defer s.Unlock()
	var commits [][]byte
	if err := json.Unmarshal(req.Commitment, &commits); err != nil {
		log.Errorf("Failed to unmarshal commitments: %v", err)
		return c.JSON(http.StatusBadRequest, &BaseResponse{Status: "error", Message: "Invalid commitment data"})
	}
	nodeID := c.Request().Header.Get("Node-ID")
	if nodeID == "" {
		return c.JSON(http.StatusBadRequest, &BaseResponse{Status: "error", Message: "Node-ID header is required"})
	}
	if _, ok := s.RegisteredNodes[nodeID]; !ok {
		return c.JSON(http.StatusUnauthorized, &BaseResponse{Status: "error", Message: "Unregistered node"})
	}
	if _, exists := s.Commitments[nodeID]; exists {
		log.Warnf("Node %s attempted to resubmit commitments", nodeID)
		return c.JSON(http.StatusForbidden, &BaseResponse{Status: "error", Message: "Commitment already submitted"})
	}
	s.Commitments[nodeID] = commits
	log.Infof("Received commitments from %s", nodeID)
	return c.JSON(http.StatusOK, &CommitmentsResponseFull{BaseResponse: BaseResponse{Status: "success"}})
}

func (s *Server) getCommitments(c echo.Context) error {
	s.Lock()
	defer s.Unlock()
	if len(s.Commitments) < s.NumNodes {
		return c.JSON(http.StatusTooEarly, &BaseResponse{Status: "error", Message: "Not all commitments received"})
	}
	serializedCommits := make(map[string][]byte)
	for nodeID, commits := range s.Commitments {
		data, err := json.Marshal(commits)
		if err != nil {
			log.Errorf("Failed to marshal commitments for %s: %v", nodeID, err)
			return c.JSON(http.StatusInternalServerError, &BaseResponse{Status: "error", Message: "Internal server error"})
		}
		serializedCommits[nodeID] = data
	}
	return c.JSON(http.StatusOK, &CommitmentsResponseFull{
		BaseResponse: BaseResponse{Status: "success"},
		Data:         &CommitmentsResponse{Commitments: serializedCommits},
	})
}

func (s *Server) submitShare(c echo.Context) error {
	req := &ShareBatchRequest{
		Shares: make(map[string]*ShareData),
	}
	if err := c.Bind(req); err != nil {
		log.Errorf("Failed to bind share batch: %v", err)
		return c.JSON(http.StatusBadRequest, &BaseResponse{Status: "error", Message: "Invalid request format"})
	}

	s.Lock()
	defer s.Unlock()

	FromNodeID := c.Request().Header.Get("Node-ID")
	if FromNodeID == "" {
		return c.JSON(http.StatusBadRequest, &BaseResponse{Status: "error", Message: "Node-ID header is required"})
	}
	if _, ok := s.RegisteredNodes[FromNodeID]; !ok {
		return c.JSON(http.StatusUnauthorized, &BaseResponse{Status: "error", Message: "Unregistered node"})
	}

	if len(req.Shares) == 0 {
		return c.JSON(http.StatusBadRequest, &BaseResponse{Status: "error", Message: "Shares map is required"})
	}

	var errores []ValidationError
	for toNodeID, share := range req.Shares {
		if share == nil {
			errores = append(errores, ValidationError{ToNodeID: toNodeID, Message: "Nil share"})
			continue
		}
		if toNodeID == FromNodeID {
			errores = append(errores, ValidationError{ToNodeID: toNodeID, Message: "Cannot include self in share batch"})
			continue
		}
		if _, ok := s.RegisteredNodes[toNodeID]; !ok {
			errores = append(errores, ValidationError{ToNodeID: toNodeID, Message: "Invalid to_node_id"})
			continue
		}
		if len(share.EncryptedShare) == 0 {
			errores = append(errores, ValidationError{ToNodeID: toNodeID, Message: "Empty share"})
		}
	}

	if len(errores) > 0 {
		return c.JSON(http.StatusBadRequest, &SharesValidationErrorResponse{
			BaseResponse: BaseResponse{Status: "error", Message: "Share validation failed"},
			Data:         &SharesValidationErrors{Errors: errores}, // Use named struct
		})
	}

	if s.Shares[FromNodeID] == nil {
		s.Shares[FromNodeID] = make(map[string]*ShareData)
	}
	for toNodeID, share := range req.Shares {
		s.Shares[FromNodeID][toNodeID] = share
	}
	log.Infof("Processed batch of %d shares from %s", len(req.Shares), FromNodeID)
	return c.JSON(http.StatusOK, &SharesResponseFull{BaseResponse: BaseResponse{Status: "success"}})
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
		return c.JSON(http.StatusTooEarly, &BaseResponse{
			Status:  "error",
			Message: fmt.Sprintf("Not all shares received: got %d, expected %d", actualShareCount, expectedShareCount),
		})
	}
	return c.JSON(http.StatusOK, &SharesResponseFull{
		BaseResponse: BaseResponse{Status: "success"},
		Data:         &SharesResponse{Shares: s.Shares},
	})
}

func (s *Server) submitPublicShare(c echo.Context) error {
	req := &PublicShareData{}
	if err := c.Bind(req); err != nil {
		log.Errorf("Failed to bind public share: %v", err)
		return c.JSON(http.StatusBadRequest, &BaseResponse{Status: "error", Message: "Invalid request format"})
	}
	if len(req.PublicShare) == 0 {
		return c.JSON(http.StatusBadRequest, &BaseResponse{Status: "error", Message: "Public share data is required"})
	}

	s.Lock()
	defer s.Unlock()
	nodeID := c.Request().Header.Get("Node-ID")
	if nodeID == "" {
		return c.JSON(http.StatusBadRequest, &BaseResponse{Status: "error", Message: "Node-ID header is required"})
	}
	if _, ok := s.RegisteredNodes[nodeID]; !ok {
		return c.JSON(http.StatusUnauthorized, &BaseResponse{Status: "error", Message: "Unregistered node"})
	}
	s.PublicShares[nodeID] = req.PublicShare
	log.Infof("Received public share from %s", nodeID)
	return c.JSON(http.StatusOK, &PublicSharesResponseFull{BaseResponse: BaseResponse{Status: "success"}})
}

func (s *Server) getPublicShares(c echo.Context) error {
	s.Lock()
	defer s.Unlock()
	if len(s.PublicShares) < s.NumNodes {
		return c.JSON(http.StatusTooEarly, &BaseResponse{
			Status:  "error",
			Message: fmt.Sprintf("Not all public shares received: got %d, expected %d", len(s.PublicShares), s.NumNodes),
		})
	}
	serializedShares := make(map[string][]byte)
	for nodeID, pubKey := range s.PublicShares {
		serializedShares[nodeID] = pubKey
	}
	log.Infof("Returning all %d public shares to client", len(s.PublicShares))
	return c.JSON(http.StatusOK, &PublicSharesResponseFull{
		BaseResponse: BaseResponse{Status: "success"},
		Data:         &PublicSharesResponse{PublicShares: serializedShares},
	})
}

func main() {
	port := os.Getenv("PORT")
	numNodesStr := os.Getenv("NUM_NODES")
	thresholdStr := os.Getenv("THRESHOLD")

	if port == "" {
		port = "8080"
	}
	if numNodesStr == "" {
		numNodesStr = "2"
	}
	if thresholdStr == "" {
		thresholdStr = "2"
	}

	numNodes, err := strconv.Atoi(numNodesStr)
	if err != nil {
		log.Fatalf("Invalid NUM_NODES: %v", err)
	}
	threshold, err := strconv.Atoi(thresholdStr)
	if err != nil {
		log.Fatalf("Invalid THRESHOLD: %v", err)
	}

	for i := 0; i < numNodes; i++ {
		uid := uuid.New().String()
		nodeIds[uid] = false
		fmt.Printf("%s\n", uid)
	}

	s, err := NewServer(numNodes, threshold)
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	e := echo.New()
	// e.Use(middleware.Logger())
	e.HideBanner = true
	e.HidePort = true
	e.Logger.SetLevel(log.INFO)

	e.GET("/health", s.health)
	e.POST("/dkg/register", s.register)
	e.GET("/dkg/nodes", s.getNodes)

	dkgGroup := e.Group("/dkg")
	dkgGroup.Use(ensureRegistrationComplete(s))
	dkgGroup.POST("/commitments", s.submitCommitment)
	dkgGroup.GET("/commitments", s.getCommitments)
	dkgGroup.POST("/shares", s.submitShare)
	dkgGroup.GET("/shares", s.getShares)
	dkgGroup.POST("/public_shares", s.submitPublicShare)
	dkgGroup.GET("/public_shares", s.getPublicShares)

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
