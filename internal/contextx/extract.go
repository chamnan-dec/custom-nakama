package contextx

import (
	"context"

	"github.com/gofrs/uuid/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func ExtractUserAndTenant(ctx context.Context) (uuid.UUID, string, error) {
	uidRaw := ctx.Value(UserIDKey{})
	if uidRaw == nil {
		return uuid.Nil, "", status.Error(codes.Unauthenticated, "Missing user id.")
	}
	userID, ok := uidRaw.(uuid.UUID)
	if !ok {
		return uuid.Nil, "", status.Error(codes.Unauthenticated, "Invalid user id format.")
	}

	tenantRaw := ctx.Value(TenantIDKey{})
	if tenantRaw == nil {
		return uuid.Nil, "", status.Error(codes.Unauthenticated, "Missing tenant id.")
	}
	tenantID, ok := tenantRaw.(string)
	if !ok || tenantID == "" {
		return uuid.Nil, "", status.Error(codes.Unauthenticated, "Invalid tenant id format.")
	}

	return userID, tenantID, nil
}
