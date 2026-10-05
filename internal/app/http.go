// Copyright Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	pfcp_networking "github.com/nextmn/go-pfcp-networking/pfcp"
	"github.com/nextmn/json-api/healthcheck"
	"github.com/nextmn/json-api/jsonapi"
	"github.com/nextmn/json-api/jsonapi/n4tosrv6"
	"github.com/nextmn/logrus-formatter/httplog"

	"github.com/gofrs/uuid/v5"
	"github.com/sirupsen/logrus"
)

type HttpServerEntity struct {
	srv     *http.Server
	routers *RouterRegistry
	closed  chan struct{}
}

type RouterRegistry struct {
	sync.RWMutex
	routers n4tosrv6.RouterMap
	pfcpSrv *pfcp_networking.PFCPEntityUP
}

func NewHttpServerEntity(httpAddr netip.AddrPort, pfcp *pfcp_networking.PFCPEntityUP) *HttpServerEntity {
	rr := RouterRegistry{
		routers: make(n4tosrv6.RouterMap),
		pfcpSrv: pfcp,
	}
	h := http.NewServeMux()
	h.HandleFunc("GET /status", rr.Status)
	h.HandleFunc("GET /routers", rr.GetRouters)
	h.HandleFunc("GET /routers/{uuid}", rr.GetRouter)
	h.HandleFunc("DELETE /routers/{uuid}", rr.DeleteRouter)
	h.HandleFunc("POST /routers", rr.PostRouter)
	logger := httplog.NewRequestLoggerMiddleware(h)
	logrus.WithFields(logrus.Fields{"http-addr": httpAddr}).Info("HTTP Server created")
	e := HttpServerEntity{
		routers: &rr,
		srv: &http.Server{
			Addr:    httpAddr.String(),
			Handler: logger,
		},
		closed: make(chan struct{}),
	}
	return &e
}

func (e *HttpServerEntity) Start(ctx context.Context) error {
	l, err := net.Listen("tcp", e.srv.Addr)
	if err != nil {
		return err
	}
	go func(ln net.Listener) {
		logrus.Info("Starting HTTP Server")
		if err := e.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logrus.WithError(err).Error("Http Server error")
		}
	}(l)
	go func(ctx context.Context) {
		defer close(e.closed)
		<-ctx.Done()
		ctxShutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 100*time.Millisecond)
		defer cancel()
		if err := e.srv.Shutdown(ctxShutdown); err == nil {
			logrus.Info("HTTP Server Shutdown")
		}
	}(ctx)
	return nil
}

func (e *HttpServerEntity) WaitShutdown(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-e.closed:
		return nil
	}
}

// get status of the controller
func (l *RouterRegistry) Status(w http.ResponseWriter, req *http.Request) {
	status := healthcheck.Status{
		Ready: (l.pfcpSrv != nil) && (l.pfcpSrv.RecoveryTimeStamp() != nil),
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	json.MarshalWrite(w, status)
}

// get a router infos
func (r *RouterRegistry) GetRouter(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Cache-Control", "no-cache")
	id := req.PathValue("uuid")
	// TODO: migrate from "gofrs/uuid" to native "uuid"
	// ==== old ====
	idUuid, err := uuid.FromString(id)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.MarshalWrite(w, jsonapi.MessageWithError{Message: "bad uuid", Error: err})
		return
	}
	// ==== new ====
	// idUuid := uuid.Parse(id)
	r.RLock()
	defer r.RUnlock()
	if val, ok := r.routers[idUuid]; ok {
		w.WriteHeader(http.StatusOK)
		json.MarshalWrite(w, val)
		return
	}
	w.WriteHeader(http.StatusNotFound)
	json.MarshalWrite(w, jsonapi.Message{Message: "router not found"})
}

// post a router infos
func (r *RouterRegistry) PostRouter(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Cache-Control", "no-cache")
	var router n4tosrv6.Router
	if err := json.UnmarshalRead(req.Body, &router); err != nil {
		logrus.WithError(err).Error("could not deserialize")
		w.WriteHeader(http.StatusBadRequest)
		json.MarshalWrite(w, jsonapi.MessageWithError{Message: "could not deserialize", Error: err})
		return
	}
	r.Lock()
	defer r.Unlock()
	for k, v := range r.routers {
		if router.Locator.Overlaps(v.Locator) {
			w.WriteHeader(http.StatusConflict)
			json.MarshalWrite(w, jsonapi.Message{Message: "this locator overlaps with locator of router " + k.String()})
			return
		}
	}

	// TODO: migrate from "gofrs/uuid" to native "uuid"
	// ==== old =====
	id, err := uuid.NewV4()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.MarshalWrite(w, jsonapi.Message{Message: "failed to generate UUID"})
	}
	// ==== new ====
	// id : =uuid.NewV4()
	for {
		// FIXME: add a context to not block the server when the pool is almost full (this would give a chance to delete old items)
		//        maybe with a retry count rather than a timeout (3 would probably be enough)
		if _, exists := r.routers[id]; !exists {
			break
		} else {
			// TODO: migrate from "gofrs/uuid" to native "uuid"
			// ==== old =====
			id, err = uuid.NewV4()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.MarshalWrite(w, jsonapi.Message{Message: "failed to generate UUID"})
			}
			// ==== new ====
			// id : =uuid.NewV4()
		}
	}
	r.routers[id] = router
	w.Header().Set("Location", fmt.Sprintf("/routers/%s", id))
	w.WriteHeader(http.StatusCreated)
	json.MarshalWrite(w, r.routers[id])
}

func (r *RouterRegistry) DeleteRouter(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Cache-Control", "no-cache")
	id := req.PathValue("uuid")
	idUuid, err := uuid.FromString(id)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.MarshalWrite(w, jsonapi.MessageWithError{Message: "bad uuid", Error: err})
		return
	}
	r.Lock()
	defer r.Unlock()
	if _, exists := r.routers[idUuid]; !exists {
		w.WriteHeader(http.StatusNotFound)
		json.MarshalWrite(w, jsonapi.Message{Message: "router not found"})
		return
	}

	delete(r.routers, idUuid)
	w.WriteHeader(http.StatusNoContent) // successful deletion
}

func (r *RouterRegistry) GetRouters(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	json.MarshalWrite(w, r.routers)
}
