// Copyright Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	pfcp_networking "github.com/nextmn/go-pfcp-networking/pfcp"
	"github.com/nextmn/json-api/healthcheck"
	"github.com/nextmn/json-api/jsonapi/n4tosrv6"

	"github.com/gin-gonic/gin"
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
	// TODO: gin.SetMode(gin.DebugMode) / gin.SetMode(gin.ReleaseMode) depending on log level
	r := gin.Default()
	r.GET("/status", rr.Status)
	r.GET("/routers", rr.GetRouters)
	r.GET("/routers/:uuid", rr.GetRouter)
	r.DELETE("/routers/:uuid", rr.DeleteRouter)
	r.POST("/routers", rr.PostRouter)
	logrus.WithFields(logrus.Fields{"http-addr": httpAddr}).Info("HTTP Server created")
	e := HttpServerEntity{
		routers: &rr,
		srv: &http.Server{
			Addr:    httpAddr.String(),
			Handler: r,
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
		select {
		case <-ctx.Done():
			ctxShutdown, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if err := e.srv.Shutdown(ctxShutdown); err != nil {
				logrus.WithError(err).Info("HTTP Server Shutdown")
			}
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
func (l *RouterRegistry) Status(c *gin.Context) {
	ready := false
	if (l.pfcpSrv != nil) && (l.pfcpSrv.RecoveryTimeStamp() != nil) {
		ready = true
	}
	status := healthcheck.Status{
		Ready: ready,
	}
	c.Header("Cache-Control", "no-cache")
	c.JSON(http.StatusOK, status)
}

// get a router infos
func (r *RouterRegistry) GetRouter(c *gin.Context) {
	id := c.Param("uuid")
	idUuid, err := uuid.FromString(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "bad uuid", "error": fmt.Sprintf("%v", err)})
		return
	}
	c.Header("Cache-Control", "no-cache")
	r.RLock()
	defer r.RUnlock()
	if val, ok := r.routers[idUuid]; ok {
		c.JSON(http.StatusOK, val)
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"message": "router not found"})
}

// post a router infos
func (r *RouterRegistry) PostRouter(c *gin.Context) {
	var router n4tosrv6.Router
	if err := c.BindJSON(&router); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "could not deserialize", "error": fmt.Sprintf("%v", err)})
		return
	}
	c.Header("Cache-Control", "no-cache")
	r.Lock()
	defer r.Unlock()
	for k, v := range r.routers {
		if router.Locator.Overlaps(v.Locator) {
			c.JSON(http.StatusConflict, gin.H{"message": "This locator overlaps with locator of router " + k.String()})
			return
		}
	}

	id, err := uuid.NewV4()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to generate UUID"})
	}
	for {
		if _, exists := r.routers[id]; !exists {
			break
		} else {
			id, err = uuid.NewV4()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to generate UUID"})
			}
		}
	}
	r.routers[id] = router
	c.Header("Location", fmt.Sprintf("/routers/%s", id))
	c.JSON(http.StatusCreated, r.routers[id])
}

func (r *RouterRegistry) DeleteRouter(c *gin.Context) {
	id := c.Param("uuid")
	idUuid, err := uuid.FromString(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "bad uuid", "error": fmt.Sprintf("%v", err)})
		return
	}
	c.Header("Cache-Control", "no-cache")
	r.Lock()
	defer r.Unlock()
	if _, exists := r.routers[idUuid]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"message": "router not found"})
		return
	}

	delete(r.routers, idUuid)
	c.Status(http.StatusNoContent) // successful deletion
}

func (r *RouterRegistry) GetRouters(c *gin.Context) {
	c.JSON(http.StatusOK, r.routers)
}
