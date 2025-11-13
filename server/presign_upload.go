package server

// File: server/presign_upload.go
//
// go get github.com/minio/minio-go/v7
// go get github.com/google/uuid
//
// Mount example (net/http):
//   svc, _ := NewPresignServiceFromEnv()
//   http.HandleFunc("/v2/presign/upload", svc.PresignUploadHandler())

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type PresignService struct {
	client        *minio.Client
	bucket        string
	region        string
	expiry        time.Duration
	publicBaseURL string
}

type presignUploadRequest struct {
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	PathPrefix  string `json:"path_prefix,omitempty"`
	ContentMD5  string `json:"content_md5,omitempty"`
}

type presignUploadResponse struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers,omitempty"`
	ObjectKey string            `json:"object_key"`
	ExpiresIn int64             `json:"expires_in"`
	PublicURL string            `json:"public_url,omitempty"`
}

// NewPresignServiceFromEnv initializes MinIO client from environment variables.
// Required: MINIO_ENDPOINT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, MINIO_BUCKET
func NewPresignServiceFromEnv() (*PresignService, error) {
	endpoint := strings.TrimSpace(os.Getenv("MINIO_ENDPOINT"))
	accessKey := os.Getenv("MINIO_ACCESS_KEY")
	secretKey := os.Getenv("MINIO_SECRET_KEY")
	useSSL, _ := strconv.ParseBool(os.Getenv("MINIO_USE_SSL"))
	bucket := os.Getenv("MINIO_BUCKET")
	region := os.Getenv("MINIO_REGION")
	publicBaseURL := strings.TrimRight(os.Getenv("MINIO_PUBLIC_BASE_URL"), "/")

	if endpoint == "" || accessKey == "" || secretKey == "" || bucket == "" {
		return nil, errors.New("MINIO_ENDPOINT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, MINIO_BUCKET are required")
	}

	expirySec := int64(600)
	if v := os.Getenv("MINIO_EXPIRY_SEC"); v != "" {
		if s, err := strconv.ParseInt(v, 10, 64); err == nil && s > 0 {
			expirySec = s
		}
	}

	cl, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
		Region: region,
	})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Ensure bucket exists (create if missing).
	exists, err := cl.BucketExists(ctx, bucket)
	if err != nil {
		return nil, err
	}
	if !exists {
		if err := cl.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: region}); err != nil {
			return nil, err
		}
	}

	return &PresignService{
		client:        cl,
		bucket:        bucket,
		region:        region,
		expiry:        time.Duration(expirySec) * time.Second,
		publicBaseURL: publicBaseURL,
	}, nil
}

// PresignUploadHandler returns a presigned PUT URL for direct upload to MinIO.
func (s *PresignService) PresignUploadHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req presignUploadRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		filename := strings.TrimSpace(req.Filename)
		if filename == "" {
			filename = "upload-" + fastRandHex(8)
		}
		filename = path.Base(filename) // sanitize

		// Object key: optional prefix + date + UUID + original filename
		u := uuid.New().String()
		datePrefix := time.Now().UTC().Format("2006/01/02")
		keyParts := []string{}
		if p := strings.Trim(req.PathPrefix, "/"); p != "" {
			keyParts = append(keyParts, p)
		}
		keyParts = append(keyParts, datePrefix, u+"-"+filename)
		objectKey := path.Clean(strings.Join(keyParts, "/"))

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Generate presigned PUT URL.
		url, err := s.client.PresignedPutObject(ctx, s.bucket, objectKey, s.expiry)
		if err != nil {
			http.Error(w, "failed to presign", http.StatusInternalServerError)
			return
		}

		// Suggested headers for the upload request (client-side).
		headers := map[string]string{}
		if ct := strings.TrimSpace(req.ContentType); ct != "" {
			headers["Content-Type"] = ct
		}
		if md5 := strings.TrimSpace(req.ContentMD5); md5 != "" {
			headers["Content-MD5"] = md5
		}

		resp := presignUploadResponse{
			Method:    "PUT",
			URL:       url.String(),
			Headers:   headers,
			ObjectKey: objectKey,
			ExpiresIn: int64(s.expiry.Seconds()),
			PublicURL: s.buildPublicURL(objectKey),
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func (s *PresignService) buildPublicURL(objectKey string) string {
	if s.publicBaseURL == "" {
		return ""
	}
	// If base URL already includes the bucket, don't duplicate it.
	base := s.publicBaseURL
	if strings.Contains(strings.TrimRight(base, "/")+"/", "/"+s.bucket+"/") {
		return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(objectKey, "/")
	}
	return strings.TrimRight(base, "/") + "/" + s.bucket + "/" + strings.TrimLeft(objectKey, "/")
}

func fastRandHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
