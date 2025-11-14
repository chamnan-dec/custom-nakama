// Copyright 2018 The Nakama Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"errors"

	"github.com/heroiclabs/nakama-common/api"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/thaibev/nakama/v3/internal/auth"
	"github.com/thaibev/nakama/v3/internal/contextx"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *ApiServer) GetAccount(ctx context.Context, in *emptypb.Empty) (*api.Account, error) {
	userID, tenantID, err := contextx.ExtractUserAndTenant(ctx)
	if err != nil {
		return nil, err
	}
	authManager := auth.GetManager()
	db, err := authManager.GetDB(tenantID)
	if err != nil {
		return nil, err
	}

	account, err := GetAccount(ctx, s.logger, db, s.statusRegistry, userID)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			return nil, status.Error(codes.NotFound, "Account not found.")
		}
		return nil, status.Error(codes.Internal, "Error retrieving user account.")
	}

	// User-facing account retrieval does not expose disable time for now.
	account.DisableTime = nil

	return account, nil
}

func (s *ApiServer) DeleteAccount(ctx context.Context, in *emptypb.Empty) (*emptypb.Empty, error) {
	userID, tenantID, err := contextx.ExtractUserAndTenant(ctx)
	if err != nil {
		return nil, err
	}
	authManager := auth.GetManager()
	db, err := authManager.GetDB(tenantID)
	if err != nil {
		return nil, err
	}

	if err := DeleteAccount(ctx, s.logger, db, s.config, s.sessionRegistry, s.sessionCache, s.tracker, userID, false); err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			return nil, status.Error(codes.NotFound, "Account not found.")
		}
		return nil, status.Error(codes.Internal, "Error deleting user account.")
	}

	return &emptypb.Empty{}, nil
}

func (s *ApiServer) UpdateAccount(ctx context.Context, in *api.UpdateAccountRequest) (*emptypb.Empty, error) {
	userID, tenantID, err := contextx.ExtractUserAndTenant(ctx)
	if err != nil {
		return nil, err
	}
	authManager := auth.GetManager()
	db, err := authManager.GetDB(tenantID)
	if err != nil {
		return nil, err
	}

	username := in.GetUsername().GetValue()
	if in.GetUsername() != nil {
		if len(username) < 1 || len(username) > 128 {
			return nil, status.Error(codes.InvalidArgument, "Username invalid, must be 1-128 bytes.")
		}
	}

	err = UpdateAccounts(ctx, s.logger, db, []*accountUpdate{{
		userID:      userID,
		username:    username,
		displayName: in.GetDisplayName(),
		timezone:    in.GetTimezone(),
		location:    in.GetLocation(),
		langTag:     in.GetLangTag(),
		avatarURL:   in.GetAvatarUrl(),
		metadata:    nil,
	}})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return nil, status.Error(codes.Internal, "Error while trying to update account.")
		}
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return &emptypb.Empty{}, nil
}
