// Copyright Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"time"

	"github.com/nextmn/srv6-ctrl/internal/config"

	pfcp_networking "github.com/nextmn/go-pfcp-networking/pfcp"

	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/message"
)

type Upf struct {
	pfcpentity *pfcp_networking.PFCPEntityUP
	closed     chan struct{}
}

func NewUpf(conf *config.CtrlConfig) *Upf {
	return &Upf{
		pfcpentity: pfcp_networking.NewPFCPEntityUP(conf.PFCPAddress.String(), conf.PFCPAddress),
		closed:     make(chan struct{}),
	}
}
func (upf *Upf) PFCPServerAddHooks(pusher *RulesPusher) error {
	if err := upf.pfcpentity.AddHandler(message.MsgTypeSessionEstablishmentRequest, func(ctx context.Context, msg pfcp_networking.ReceivedMessage) (*pfcp_networking.OutcomingMessage, error) {
		out, err := pfcp_networking.DefaultSessionEstablishmentRequestHandler(ctx, msg)
		if err == nil {
			go upf.pfcpentity.LogPFCPRules()
			pusher.updateRoutersRules(ctx, message.MsgTypeSessionEstablishmentRequest, msg, upf.pfcpentity)
		}
		return out, err
	}); err != nil {
		return err
	}
	if err := upf.pfcpentity.AddHandler(message.MsgTypeSessionModificationRequest, func(ctx context.Context, msg pfcp_networking.ReceivedMessage) (*pfcp_networking.OutcomingMessage, error) {
		out, err := pfcp_networking.DefaultSessionModificationRequestHandler(ctx, msg)
		if err == nil {
			go upf.pfcpentity.LogPFCPRules()
			pusher.updateRoutersRules(ctx, message.MsgTypeSessionModificationRequest, msg, upf.pfcpentity)
		}
		return out, err
	}); err != nil {
		return err
	}
	return nil
}

func NewHttpServer(conf *config.CtrlConfig, srv6Srv *pfcp_networking.PFCPEntityUP) *HttpServerEntity {
	HTTPServer := NewHttpServerEntity(conf.Control.BindAddr, srv6Srv)
	return HTTPServer
}

func (upf *Upf) Start(ctx context.Context) error {
	go func(ctx context.Context, srv *pfcp_networking.PFCPEntityUP) {
		logrus.Info("Starting PFCP Server")
		if err := srv.ListenAndServeContext(ctx); err != nil {
			logrus.WithError(err).Error("PFCP Server Shutdown")
			close(upf.closed)
		}
	}(ctx, upf.pfcpentity)
	ctxTimeout, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if err := upf.pfcpentity.WaitReady(ctxTimeout); err != nil {
		return err
	}
	return nil
}

func (upf *Upf) WaitShutdown(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-upf.closed:
		return nil
	}
}
