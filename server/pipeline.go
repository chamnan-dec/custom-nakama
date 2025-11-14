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
	"fmt"

	"github.com/heroiclabs/nakama-common/rtapi"
	"github.com/thaibev/nakama/v3/internal/config"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
)

type Pipeline struct {
	logger               *zap.Logger
	config               config.Config
	protojsonMarshaler   *protojson.MarshalOptions
	protojsonUnmarshaler *protojson.UnmarshalOptions
	sessionRegistry      SessionRegistry
	statusRegistry       StatusRegistry
	tracker              Tracker
	router               MessageRouter
	node                 string
}

func NewPipeline(logger *zap.Logger, config config.Config, protojsonMarshaler *protojson.MarshalOptions, protojsonUnmarshaler *protojson.UnmarshalOptions, sessionRegistry SessionRegistry, statusRegistry StatusRegistry, tracker Tracker, router MessageRouter) *Pipeline {
	return &Pipeline{
		logger:               logger,
		config:               config,
		protojsonMarshaler:   protojsonMarshaler,
		protojsonUnmarshaler: protojsonUnmarshaler,
		sessionRegistry:      sessionRegistry,
		statusRegistry:       statusRegistry,
		tracker:              tracker,
		router:               router,
		node:                 config.GetName(),
	}
}

func (p *Pipeline) ProcessRequest(logger *zap.Logger, session Session, in *rtapi.Envelope) bool {
	if logger.Core().Enabled(zap.DebugLevel) { // remove extra heavy reflection processing
		logger.Debug(fmt.Sprintf("Received %T message", in.Message), zap.Any("message", in.Message))
	}

	if in.Message == nil {
		_ = session.Send(&rtapi.Envelope{Cid: in.Cid, Message: &rtapi.Envelope_Error{Error: &rtapi.Error{
			Code:    int32(rtapi.Error_MISSING_PAYLOAD),
			Message: "Missing message.",
		}}}, true)
		return false
	}

	var pipelineFn func(*zap.Logger, Session, *rtapi.Envelope) (bool, *rtapi.Envelope)

	switch in.Message.(type) {
	case *rtapi.Envelope_ChannelJoin:
		pipelineFn = p.channelJoin
	case *rtapi.Envelope_ChannelLeave:
		pipelineFn = p.channelLeave
	case *rtapi.Envelope_ChannelMessageSend:
		pipelineFn = p.channelMessageSend
	case *rtapi.Envelope_ChannelMessageUpdate:
		pipelineFn = p.channelMessageUpdate
	case *rtapi.Envelope_ChannelMessageRemove:
		pipelineFn = p.channelMessageRemove
	case *rtapi.Envelope_Ping:
		pipelineFn = p.ping
	case *rtapi.Envelope_Pong:
		pipelineFn = p.pong
	default:
		// If we reached this point the envelope was valid but the contents are missing or unknown.
		// Usually caused by a version mismatch, and should cause the session making this pipeline request to close.
		logger.Error("Unrecognizable payload received.", zap.Any("payload", in))
		_ = session.Send(&rtapi.Envelope{Cid: in.Cid, Message: &rtapi.Envelope_Error{Error: &rtapi.Error{
			Code:    int32(rtapi.Error_UNRECOGNIZED_PAYLOAD),
			Message: "Unrecognized message.",
		}}}, true)
		return false
	}

	var messageName, _ string

	switch in.Message.(type) {
	case *rtapi.Envelope_Rpc:
		// No before/after hooks on RPC.
	default:
		messageName = fmt.Sprintf("%T", in.Message)
		// messageNameID = strings.ToLower(messageName)

		// if fn := p.runtime.BeforeRt(messageNameID); fn != nil {
		// 	hookResult, hookErr := fn(session.Context(), logger, session.UserID().String(), session.Username(), session.Vars(), session.Expiry(), session.ID().String(), session.ClientIP(), session.ClientPort(), session.Lang(), in)

		// 	if hookErr != nil {
		// 		// Errors from before hooks do not close the session.
		// 		_ = session.Send(&rtapi.Envelope{Cid: in.Cid, Message: &rtapi.Envelope_Error{Error: &rtapi.Error{
		// 			Code:    int32(rtapi.Error_RUNTIME_FUNCTION_EXCEPTION),
		// 			Message: hookErr.Error(),
		// 		}}}, true)
		// 		return true
		// 	} else if hookResult == nil {
		// 		// If result is nil, requested resource is disabled. Sessions calling disabled resources will be closed.
		// 		logger.Warn("Intercepted a disabled resource.", zap.String("resource", messageName))
		// 		_ = session.Send(&rtapi.Envelope{Cid: in.Cid, Message: &rtapi.Envelope_Error{Error: &rtapi.Error{
		// 			Code:    int32(rtapi.Error_UNRECOGNIZED_PAYLOAD),
		// 			Message: "Requested resource was not found.",
		// 		}}}, true)
		// 		return false
		// 	}

		// 	in = hookResult
		// }
	}

	success, _ := pipelineFn(logger, session, in)

	if success && messageName != "" {
		// Unsuccessful operations do not trigger after hooks.
		// if fn := p.runtime.AfterRt(messageNameID); fn != nil {
		// 	_ = fn(session.Context(), logger, session.UserID().String(), session.Username(), session.Vars(), session.Expiry(), session.ID().String(), session.ClientIP(), session.ClientPort(), session.Lang(), out, in)
		// }
	}

	return true
}
