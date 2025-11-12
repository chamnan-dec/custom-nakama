// Copyright 2021 The Nakama Authors
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

	"github.com/gofrs/uuid/v5"
	"github.com/heroiclabs/nakama-common/api"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *ApiServer) SessionRefresh(ctx context.Context, in *api.SessionRefreshRequest) (*api.Session, error) {
	db, err := GetDB("region_a")
	if err != nil {
		return nil, err
	}
	// Before hook.
	if in.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "Refresh token is required.")
	}

	userID, username, vars, tokenId, tokenIssuedAt, err := SessionRefresh(ctx, s.logger, db, s.config, s.sessionCache, in.Token)
	if err != nil {
		return nil, err
	}

	// Use updated vars if they are provided, otherwise use existing ones from refresh token.
	useVars := in.Vars
	if useVars == nil {
		useVars = vars
	}
	userIDStr := userID.String()

	//newTokenId := uuid.Must(uuid.NewV4()).String()
	//token, tokenExp := generateToken(s.config, newTokenId, userIDStr, username, useVars)
	//refreshToken, refreshTokenExp := generateRefreshToken(s.config, newTokenId, userIDStr, username, useVars)
	//s.sessionCache.Remove(userID, tokenExp, "", refreshTokenExp, tokenId)
	//s.sessionCache.Add(userID, tokenExp, newTokenId, refreshTokenExp, newTokenId)
	//session := &api.Session{Created: false, Token: token, RefreshToken: refreshToken}

	token, tokenExp := generateToken(s.config, tokenId, tokenIssuedAt, userIDStr, username, useVars)
	refreshToken, refreshTokenExp := generateRefreshToken(s.config, tokenId, tokenIssuedAt, userIDStr, username, useVars)
	s.sessionCache.Add(userID, tokenExp, tokenId, refreshTokenExp, tokenId)
	session := &api.Session{Created: false, Token: token, RefreshToken: refreshToken}

	return session, nil
}

func (s *ApiServer) SessionLogout(ctx context.Context, in *api.SessionLogoutRequest) (*emptypb.Empty, error) {
	userID := ctx.Value(ctxUserIDKey{}).(uuid.UUID)

	if err := SessionLogout(s.config, s.sessionCache, userID, in.Token, in.RefreshToken); err != nil {
		if err == ErrSessionTokenInvalid {
			return nil, status.Error(codes.InvalidArgument, "Session token invalid.")
		}
		if err == ErrRefreshTokenInvalid {
			return nil, status.Error(codes.InvalidArgument, "Refresh token invalid.")
		}
		s.logger.Error("Error processing session logout.", zap.Error(err))
		return nil, status.Error(codes.Internal, "Error processing session logout.")
	}

	return &emptypb.Empty{}, nil
}
