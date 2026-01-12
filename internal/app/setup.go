// Copyright Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"time"

	"github.com/nextmn/srv6-ctrl/internal/config"
)

type Setup struct {
	HTTPServer  *HttpServerEntity
	Upf         *Upf
	RulesPusher *RulesPusher
}

func NewSetup(conf *config.CtrlConfig) Setup {
	upf := NewUpf(conf)
	return Setup{
		HTTPServer:  NewHttpServer(conf, upf.pfcpentity),
		Upf:         upf,
		RulesPusher: NewRulesPusher(conf),
	}
}

func (s Setup) Run(ctx context.Context) error {
	defer func() {
		ctxShutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 1*time.Second)
		defer cancel()
		s.HTTPServer.WaitShutdown(ctxShutdown)
		s.Upf.WaitShutdown(ctxShutdown)
	}()
	if err := s.Upf.PFCPServerAddHooks(s.RulesPusher); err != nil {
		return err
	}
	if err := s.Upf.Start(ctx); err != nil {
		return err
	}
	if err := s.HTTPServer.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}
