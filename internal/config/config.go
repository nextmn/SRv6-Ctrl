// Copyright Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package config

import (
	"io/ioutil"
	"net/netip"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func ParseConf(file string) (*CtrlConfig, error) {
	var conf CtrlConfig
	path, err := filepath.Abs(file)
	if err != nil {
		return nil, err
	}
	yamlFile, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err = yaml.Unmarshal(yamlFile, &conf); err != nil {
		return nil, err
	}
	return &conf, nil
}

type CtrlConfig struct {
	PFCPAddress netip.Addr `yaml:"pfcp-address"`
	Control     Control    `yaml:"control"`
	Logger      *Logger    `yaml:"logger,omitempty"`
	Uplink      []Rule     `yaml:"uplink"`
	Downlink    []Rule     `yaml:"downlink"`
}
