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

	"github.com/gofrs/uuid/v5"
	"github.com/heroiclabs/nakama-common/api"
	"github.com/heroiclabs/nakama-common/runtime"
	"github.com/thaibev/nakama/v3/internal/auth"
	"github.com/thaibev/nakama/v3/internal/contextx"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *ApiServer) CreateGroup(ctx context.Context, in *api.CreateGroupRequest) (*api.Group, error) {
	userID, tenantID, err := contextx.ExtractUserAndTenant(ctx)
	if err != nil {
		return nil, err
	}
	authManager := auth.GetManager()
	db, err := authManager.GetDB(tenantID)
	if err != nil {
		return nil, err
	}

	if in.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "Group name must be set.")
	}

	maxCount := 100
	if mc := in.MaxCount; mc != 0 {
		if mc < 1 {
			return nil, status.Error(codes.InvalidArgument, "Group max count must be >= 1 when set.")
		}
		maxCount = int(mc)
	}

	group, err := CreateGroup(ctx, s.logger, db, userID, userID, in.GetName(), in.GetLangTag(), in.GetDescription(), in.GetAvatarUrl(), "", in.GetOpen(), maxCount)
	if err != nil {
		if err == runtime.ErrGroupNameInUse {
			return nil, status.Error(codes.AlreadyExists, "Group name is in use.")
		}
		return nil, status.Error(codes.Internal, "Error while trying to create group.")
	}

	return group, nil
}

func (s *ApiServer) UpdateGroup(ctx context.Context, in *api.UpdateGroupRequest) (*emptypb.Empty, error) {
	userID, tenantID, err := contextx.ExtractUserAndTenant(ctx)
	if err != nil {
		return nil, err
	}
	authManager := auth.GetManager()
	db, err := authManager.GetDB(tenantID)
	if err != nil {
		return nil, err
	}

	if in.GetGroupId() == "" {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be set.")
	}

	groupID, err := uuid.FromString(in.GetGroupId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be a valid ID.")
	}

	if in.GetName() != nil {
		if len(in.GetName().String()) < 1 {
			return nil, status.Error(codes.InvalidArgument, "Group name cannot be empty.")
		}
	}

	if in.GetLangTag() != nil {
		if len(in.GetLangTag().String()) < 1 {
			return nil, status.Error(codes.InvalidArgument, "Group language cannot be empty.")
		}
	}

	if err = UpdateGroup(ctx, s.logger, db, groupID, userID, uuid.Nil, in.GetName(), in.GetLangTag(), in.GetDescription(), in.GetAvatarUrl(), nil, in.GetOpen(), -1); err != nil {
		switch err {
		case runtime.ErrGroupPermissionDenied:
			return nil, status.Error(codes.NotFound, "Group not found or you're not allowed to update.")
		case runtime.ErrGroupNoUpdateOps:
			return nil, status.Error(codes.InvalidArgument, "Specify at least one field to update.")
		case runtime.ErrGroupNotUpdated:
			return nil, status.Error(codes.InvalidArgument, "No new fields in group update.")
		case runtime.ErrGroupNameInUse:
			return nil, status.Error(codes.InvalidArgument, "Group name is in use.")
		default:
			return nil, status.Error(codes.Internal, "Error while trying to update group.")
		}
	}

	return &emptypb.Empty{}, nil
}

func (s *ApiServer) DeleteGroup(ctx context.Context, in *api.DeleteGroupRequest) (*emptypb.Empty, error) {
	userID, tenantID, err := contextx.ExtractUserAndTenant(ctx)
	if err != nil {
		return nil, err
	}
	authManager := auth.GetManager()
	db, err := authManager.GetDB(tenantID)
	if err != nil {
		return nil, err
	}

	if in.GetGroupId() == "" {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be set.")
	}

	groupID, err := uuid.FromString(in.GetGroupId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be a valid ID.")
	}

	err = DeleteGroup(ctx, s.logger, db, s.tracker, groupID, userID)
	if err != nil {
		if err == runtime.ErrGroupPermissionDenied {
			return nil, status.Error(codes.InvalidArgument, "Group not found or you're not allowed to delete.")
		}
		return nil, status.Error(codes.Internal, "Error while trying to delete group.")
	}

	return &emptypb.Empty{}, nil
}

func (s *ApiServer) JoinGroup(ctx context.Context, in *api.JoinGroupRequest) (*emptypb.Empty, error) {
	userID, tenantID, err := contextx.ExtractUserAndTenant(ctx)
	username := ctx.Value(contextx.UsernameKey{}).(string)
	if err != nil {
		return nil, err
	}
	authManager := auth.GetManager()
	db, err := authManager.GetDB(tenantID)
	if err != nil {
		return nil, err
	}

	if in.GetGroupId() == "" {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be set.")
	}

	groupID, err := uuid.FromString(in.GetGroupId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be a valid ID.")
	}

	err = JoinGroup(ctx, s.logger, db, s.tracker, s.router, groupID, userID, username)
	if err != nil {
		switch {
		case errors.Is(err, runtime.ErrGroupNotFound):
			return nil, status.Error(codes.NotFound, "Group not found.")
		case errors.Is(err, runtime.ErrGroupFull):
			return nil, status.Error(codes.InvalidArgument, "Group is full.")
		default:
			return nil, status.Error(codes.Internal, "Error while trying to join group.")
		}
	}

	return &emptypb.Empty{}, nil
}

func (s *ApiServer) LeaveGroup(ctx context.Context, in *api.LeaveGroupRequest) (*emptypb.Empty, error) {
	userID, tenantID, err := contextx.ExtractUserAndTenant(ctx)
	if err != nil {
		return nil, err
	}
	authManager := auth.GetManager()
	db, err := authManager.GetDB(tenantID)
	if err != nil {
		return nil, err
	}
	username := ctx.Value(contextx.UsernameKey{}).(string)

	if in.GetGroupId() == "" {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be set.")
	}

	groupID, err := uuid.FromString(in.GetGroupId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be a valid ID.")
	}

	err = LeaveGroup(ctx, s.logger, db, s.tracker, s.router, s.streamManager, groupID, userID, username)
	if err != nil {
		if err == runtime.ErrGroupLastSuperadmin {
			return nil, status.Error(codes.InvalidArgument, "Cannot leave group when you are the last superadmin.")
		}
		return nil, status.Error(codes.Internal, "Error while trying to leave group.")
	}

	return &emptypb.Empty{}, nil
}

func (s *ApiServer) AddGroupUsers(ctx context.Context, in *api.AddGroupUsersRequest) (*emptypb.Empty, error) {
	userID, tenantID, err := contextx.ExtractUserAndTenant(ctx)
	if err != nil {
		return nil, err
	}
	authManager := auth.GetManager()
	db, err := authManager.GetDB(tenantID)
	if err != nil {
		return nil, err
	}

	if in.GetGroupId() == "" {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be set.")
	}

	groupID, err := uuid.FromString(in.GetGroupId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be a valid ID.")
	}

	if len(in.GetUserIds()) == 0 {
		return &emptypb.Empty{}, nil
	}

	userIDs := make([]uuid.UUID, 0, len(in.GetUserIds()))
	for _, id := range in.GetUserIds() {
		uid := uuid.FromStringOrNil(id)
		if uid == uuid.Nil {
			return nil, status.Error(codes.InvalidArgument, "User ID must be a valid ID.")
		}
		userIDs = append(userIDs, uid)
	}

	err = AddGroupUsers(ctx, s.logger, db, s.tracker, s.router, userID, groupID, userIDs)
	if err != nil {
		switch {
		case errors.Is(err, runtime.ErrGroupPermissionDenied):
			return nil, status.Error(codes.NotFound, "Group not found or permission denied.")
		case errors.Is(err, runtime.ErrGroupFull):
			return nil, status.Error(codes.InvalidArgument, "Group is full.")
		case errors.Is(err, runtime.ErrGroupUserNotFound):
			return nil, status.Error(codes.InvalidArgument, "One or more users not found.")
		default:
			return nil, status.Error(codes.Internal, "Error while trying to add users to a group.")
		}
	}

	return &emptypb.Empty{}, nil
}

func (s *ApiServer) BanGroupUsers(ctx context.Context, in *api.BanGroupUsersRequest) (*emptypb.Empty, error) {
	userID, tenantID, err := contextx.ExtractUserAndTenant(ctx)
	if err != nil {
		return nil, err
	}
	authManager := auth.GetManager()
	db, err := authManager.GetDB(tenantID)
	if err != nil {
		return nil, err
	}

	if in.GetGroupId() == "" {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be set.")
	}

	groupID, err := uuid.FromString(in.GetGroupId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be a valid ID.")
	}

	if len(in.GetUserIds()) == 0 {
		return &emptypb.Empty{}, nil
	}

	userIDs := make([]uuid.UUID, 0, len(in.GetUserIds()))
	for _, id := range in.GetUserIds() {
		uid := uuid.FromStringOrNil(id)
		if uid == uuid.Nil {
			return nil, status.Error(codes.InvalidArgument, "User ID must be a valid ID.")
		}
		userIDs = append(userIDs, uid)
	}

	if err = BanGroupUsers(ctx, s.logger, db, s.tracker, s.router, s.streamManager, userID, groupID, userIDs); err != nil {
		if err == runtime.ErrGroupPermissionDenied {
			return nil, status.Error(codes.NotFound, "Group not found or permission denied.")
		}
		return nil, status.Error(codes.Internal, "Error while trying to ban users from a group.")
	}

	return &emptypb.Empty{}, nil
}

func (s *ApiServer) KickGroupUsers(ctx context.Context, in *api.KickGroupUsersRequest) (*emptypb.Empty, error) {
	userID, tenantID, err := contextx.ExtractUserAndTenant(ctx)
	if err != nil {
		return nil, err
	}
	authManager := auth.GetManager()
	db, err := authManager.GetDB(tenantID)
	if err != nil {
		return nil, err
	}

	if in.GetGroupId() == "" {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be set.")
	}

	groupID, err := uuid.FromString(in.GetGroupId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be a valid ID.")
	}

	if len(in.GetUserIds()) == 0 {
		return &emptypb.Empty{}, nil
	}

	userIDs := make([]uuid.UUID, 0, len(in.GetUserIds()))
	for _, id := range in.GetUserIds() {
		uid := uuid.FromStringOrNil(id)
		if uid == uuid.Nil {
			return nil, status.Error(codes.InvalidArgument, "User ID must be a valid ID.")
		}
		userIDs = append(userIDs, uid)
	}

	if err = KickGroupUsers(ctx, s.logger, db, s.tracker, s.router, s.streamManager, userID, groupID, userIDs, false); err != nil {
		if err == runtime.ErrGroupPermissionDenied {
			return nil, status.Error(codes.NotFound, "Group not found or permission denied.")
		}
		return nil, status.Error(codes.Internal, "Error while trying to kick users from a group.")
	}

	return &emptypb.Empty{}, nil
}

func (s *ApiServer) PromoteGroupUsers(ctx context.Context, in *api.PromoteGroupUsersRequest) (*emptypb.Empty, error) {
	userID, tenantID, err := contextx.ExtractUserAndTenant(ctx)
	if err != nil {
		return nil, err
	}
	authManager := auth.GetManager()
	db, err := authManager.GetDB(tenantID)
	if err != nil {
		return nil, err
	}

	if in.GetGroupId() == "" {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be set.")
	}

	groupID, err := uuid.FromString(in.GetGroupId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be a valid ID.")
	}

	if len(in.GetUserIds()) == 0 {
		return &emptypb.Empty{}, nil
	}

	userIDs := make([]uuid.UUID, 0, len(in.GetUserIds()))
	for _, id := range in.GetUserIds() {
		uid := uuid.FromStringOrNil(id)
		if uid == uuid.Nil {
			return nil, status.Error(codes.InvalidArgument, "User ID must be a valid ID.")
		}
		userIDs = append(userIDs, uid)
	}

	err = PromoteGroupUsers(ctx, s.logger, db, s.router, userID, groupID, userIDs)
	if err != nil {
		switch {
		case errors.Is(err, runtime.ErrGroupPermissionDenied):
			return nil, status.Error(codes.NotFound, "Group not found or permission denied.")
		case errors.Is(err, runtime.ErrGroupFull):
			return nil, status.Error(codes.InvalidArgument, "Group is full.")
		default:
			return nil, status.Error(codes.Internal, "Error while trying to promote users in a group.")
		}
	}

	return &emptypb.Empty{}, nil
}

func (s *ApiServer) ListGroupUsers(ctx context.Context, in *api.ListGroupUsersRequest) (*api.GroupUserList, error) {
	_, tenantID, err := contextx.ExtractUserAndTenant(ctx)
	if err != nil {
		return nil, err
	}
	authManager := auth.GetManager()
	db, err := authManager.GetDB(tenantID)
	if err != nil {
		return nil, err
	}
	if in.GetGroupId() == "" {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be set.")
	}

	groupID, err := uuid.FromString(in.GetGroupId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be a valid ID.")
	}

	limit := 100
	if in.GetLimit() != nil {
		if in.GetLimit().Value < 1 || in.GetLimit().Value > 100 {
			return nil, status.Error(codes.InvalidArgument, "Invalid limit - limit must be between 1 and 100.")
		}
		limit = int(in.GetLimit().Value)
	}

	state := in.GetState()
	if state != nil {
		if state := in.GetState().Value; state < 0 || state > 4 {
			return nil, status.Error(codes.InvalidArgument, "Invalid state - state must be between 0 and 4.")
		}
	}

	groupUsers, err := ListGroupUsers(ctx, s.logger, db, s.statusRegistry, groupID, limit, state, in.GetCursor())
	if err != nil {
		if err == runtime.ErrGroupUserInvalidCursor {
			return nil, status.Error(codes.InvalidArgument, "Cursor is invalid.")
		}
		return nil, status.Error(codes.Internal, "Error while trying to list users in a group.")
	}

	return groupUsers, nil
}

func (s *ApiServer) DemoteGroupUsers(ctx context.Context, in *api.DemoteGroupUsersRequest) (*emptypb.Empty, error) {
	userID, tenantID, err := contextx.ExtractUserAndTenant(ctx)
	if err != nil {
		return nil, err
	}
	authManager := auth.GetManager()
	db, err := authManager.GetDB(tenantID)
	if err != nil {
		return nil, err
	}

	if in.GetGroupId() == "" {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be set.")
	}

	groupID, err := uuid.FromString(in.GetGroupId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be a valid ID.")
	}

	if len(in.GetUserIds()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "User IDs must be set.")
	}

	userIDs := make([]uuid.UUID, 0, len(in.GetUserIds()))
	for _, id := range in.GetUserIds() {
		uid := uuid.FromStringOrNil(id)
		if uid == uuid.Nil {
			return nil, status.Error(codes.InvalidArgument, "User ID must be a valid ID.")
		}
		userIDs = append(userIDs, uid)
	}

	err = DemoteGroupUsers(ctx, s.logger, db, s.router, userID, groupID, userIDs)
	if err != nil {
		switch {
		case errors.Is(err, runtime.ErrGroupPermissionDenied):
			return nil, status.Error(codes.NotFound, "Group not found or permission denied.")
		case errors.Is(err, runtime.ErrGroupFull):
			return nil, status.Error(codes.InvalidArgument, "Group is full.")
		default:
			return nil, status.Error(codes.Internal, "Error while trying to demote users in a group.")
		}
	}

	return &emptypb.Empty{}, nil
}

func (s *ApiServer) ListUserGroups(ctx context.Context, in *api.ListUserGroupsRequest) (*api.UserGroupList, error) {
	_, tenantID, err := contextx.ExtractUserAndTenant(ctx)
	if err != nil {
		return nil, err
	}
	authManager := auth.GetManager()
	db, err := authManager.GetDB(tenantID)
	if err != nil {
		return nil, err
	}
	if in.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "User ID must be set.")
	}

	userID, err := uuid.FromString(in.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "Group ID must be a valid ID.")
	}

	limit := 100
	if in.GetLimit() != nil {
		if in.GetLimit().Value < 1 || in.GetLimit().Value > 100 {
			return nil, status.Error(codes.InvalidArgument, "Invalid limit - limit must be between 1 and 100.")
		}
		limit = int(in.GetLimit().Value)
	}

	state := in.GetState()
	if state != nil {
		if state := in.GetState().Value; state < 0 || state > 4 {
			return nil, status.Error(codes.InvalidArgument, "Invalid state - state must be between 0 and 4.")
		}
	}

	userGroups, err := ListUserGroups(ctx, s.logger, db, userID, limit, state, in.GetCursor())
	if err != nil {
		if err == runtime.ErrUserGroupInvalidCursor {
			return nil, status.Error(codes.InvalidArgument, "Cursor is invalid.")
		}
		return nil, status.Error(codes.Internal, "Error while trying to list groups for a user.")
	}

	return userGroups, nil
}

func (s *ApiServer) ListGroups(ctx context.Context, in *api.ListGroupsRequest) (*api.GroupList, error) {
	_, tenantID, err := contextx.ExtractUserAndTenant(ctx)
	if err != nil {
		return nil, err
	}
	authManager := auth.GetManager()
	db, err := authManager.GetDB(tenantID)
	if err != nil {
		return nil, err
	}
	limit := 1
	if in.GetLimit() != nil {
		if in.GetLimit().Value < 1 || in.GetLimit().Value > 100 {
			return nil, status.Error(codes.InvalidArgument, "Invalid limit - limit must be between 1 and 100.")
		}
		limit = int(in.GetLimit().Value)
	}

	var open *bool
	openIn := in.GetOpen()
	if openIn != nil {
		open = new(bool)
		*open = openIn.GetValue()
	}

	edgeCount := -1
	if in.Members != nil {
		edgeCount = int(in.Members.GetValue())
	}

	groups, err := ListGroups(ctx, s.logger, db, in.GetName(), in.GetLangTag(), open, edgeCount, limit, in.GetCursor())
	if err != nil {
		if sErr, ok := err.(*statusError); ok {
			return nil, sErr.Status()
		}
		return nil, status.Error(codes.Internal, "Error while trying to list groups.")
	}

	return groups, nil
}
