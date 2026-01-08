// Copyright Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sync"

	pfcp_networking "github.com/nextmn/go-pfcp-networking/pfcp"
	pfcpapi "github.com/nextmn/go-pfcp-networking/pfcp/api"
	"github.com/nextmn/go-pfcp-networking/pfcputil"
	"github.com/nextmn/json-api/jsonapi"
	"github.com/nextmn/json-api/jsonapi/n4tosrv6"
	"github.com/nextmn/rfc9433/encoding"
	"github.com/nextmn/srv6-ctrl/internal/config"

	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

const UserAgent = "go-github-nextmn-srv6-ctrl"

type RulesPusher struct {
	uplink   []config.Rule
	downlink []config.Rule
	ues      sync.Map
}

type RuleAction struct {
	Url          *url.URL
	Action       *n4tosrv6.Action
	GtpDstPrefix netip.Prefix
}

type HandoverInfos struct {
	UlTargetSrgw jsonapi.Fteid
	DlTargetGnb  *jsonapi.Fteid
}

type ueInfos struct {
	sync.Mutex

	UplinkFTeid  jsonapi.Fteid
	DownlinkTeid uint32
	Gnb          string
	Pushed       bool

	HandoverInfos *HandoverInfos
	AnchorsRules  []*RuleAction
	AnchorsLock   sync.RWMutex

	SRGWRules []*RuleAction
	SRGWLock  sync.RWMutex
}

func NewRulesPusher(config *config.CtrlConfig) *RulesPusher {
	return &RulesPusher{
		uplink:   config.Uplink,
		downlink: config.Downlink,
		ues:      sync.Map{},
	}
}

func (pusher *RulesPusher) pushUpdateAction(ctx context.Context, client http.Client, url *url.URL, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url.String(), bytes.NewBuffer(data))
	if err != nil {
		logrus.WithError(err).Error("could not create http request")
		return err
	}
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	resp, err := client.Do(req)
	if err != nil {
		logrus.WithError(err).Error("Could not push update action: server not responding")
		return fmt.Errorf("Could not push update action: server not responding")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 400 {
		logrus.WithError(err).Error("HTTP Bad Request")
		return fmt.Errorf("HTTP Bad request")
	} else if resp.StatusCode >= 500 {
		logrus.WithError(err).Error("HTTP internal error")
		return fmt.Errorf("HTTP internal error")
	}
	return nil
}
func (pusher *RulesPusher) pushSingleRule(ctx context.Context, client http.Client, uri jsonapi.ControlURI, data []byte) (*url.URL, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri.JoinPath("rules").String(), bytes.NewBuffer(data))
	if err != nil {
		logrus.WithError(err).Error("could not create http request")
		return nil, err
	}
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	resp, err := client.Do(req)
	if err != nil {
		logrus.WithError(err).Error("Could not push rules: server not responding")
		return nil, fmt.Errorf("Could not push rules: server not responding")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 400 {
		logrus.WithError(err).Error("HTTP Bad Request")
		return nil, fmt.Errorf("HTTP Bad request")
	} else if resp.StatusCode >= 500 {
		logrus.WithError(err).Error("HTTP internal error")
		return nil, fmt.Errorf("HTTP internal error")
	} else if resp.StatusCode == 201 {
		loc := resp.Header.Get("Location")
		uloc, err := url.Parse(loc)
		if err != nil {
			return nil, err
		}
		return uri.ResolveReference(uloc), nil
	}
	return nil, fmt.Errorf("No Location provided")
}

func gnbInArea(gnb netip.Addr, area []netip.Prefix) bool {
	for _, area_prefix := range area {
		if area_prefix.Contains(gnb) {
			return true
		}
	}
	return false
}

func (pusher *RulesPusher) pushHandoverAcrossAreas(ctx context.Context, ue_ip string) error {
	i, ok := pusher.ues.Load(ue_ip)
	if !ok {
		return fmt.Errorf("UE not in ue list")
	}
	infos := i.(*ueInfos)
	infos.Lock()
	defer infos.Unlock()
	if !infos.Pushed {
		return nil // not pushed, nothing to do
	}
	if infos.HandoverInfos == nil {
		return nil // no handover
	}
	if infos.HandoverInfos.DlTargetGnb == nil {
		return nil // not enough info, yet
	}
	gnb_addr := infos.HandoverInfos.DlTargetGnb.Addr
	ue_addr, err := netip.ParseAddr(ue_ip)
	if err != nil {
		return err
	}
	client := http.Client{}
	logrus.WithFields(logrus.Fields{
		"dl-teid": infos.HandoverInfos.DlTargetGnb.Teid,
		"dl-addr": infos.HandoverInfos.DlTargetGnb.Addr,
		"ul-teid": infos.HandoverInfos.UlTargetSrgw.Teid,
		"ul-addr": infos.HandoverInfos.UlTargetSrgw.Addr,
		"ue-ip":   ue_ip,
	}).Info("Pushing Handover Rules")
	var wg sync.WaitGroup

	for _, r := range pusher.uplink {
		if r.Service == nil {
			return fmt.Errorf("service configurated is nil for uplink rule")
		}
		//TODO: add ArgMobSession
		srh, err := n4tosrv6.NewSRH(r.SegmentsList)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"segments-list": r.SegmentsList,
			}).WithError(err).Error("Creation of SRH uplink failed")
			return err
		}
		var area []netip.Prefix
		if r.Area != nil {
			area = *r.Area
		} else {
			// if no area is defined, create a new-one with only this gnb
			area = []netip.Prefix{netip.PrefixFrom(gnb_addr, 32)}
		}
		// check infos.Gnb in area
		if !gnbInArea(gnb_addr, area) {
			continue
		}

		action := n4tosrv6.Action{
			SRH: *srh,
		}
		rule := n4tosrv6.Rule{
			Enabled: r.Enabled,
			Type:    "uplink",
			Match: n4tosrv6.Match{
				Header: &n4tosrv6.GtpHeader{
					OuterIpSrc: area,
					FTeid:      infos.HandoverInfos.UlTargetSrgw,
					InnerIpSrc: &ue_addr,
				},
				Payload: &n4tosrv6.Payload{
					// TODO: allow multiple services
					Dst: *r.Service,
				},
			},
			Action: action,
		}
		rule_json, err := json.Marshal(rule)
		if err != nil {
			logrus.WithError(err).Error("Could not marshal json")
			return err
		}
		wg.Add(1)
		// TODO: remove old rules
		go func() error {
			defer wg.Done()
			//infos.SRGWLock.Lock()
			//defer infos.SRGWLock.Unlock()
			_, _ = pusher.pushSingleRule(ctx, client, r.ControlURI, rule_json)
			// TODO: store this (after old rules are removed)
			//if err == nil {
			//	infos.SRGWRules = append(infos.SRGWRules, &RuleAction{
			//		Url:    url,
			//		Action: &action,
			//	})
			//}
			return err
		}()

	}

	for _, r := range pusher.downlink {
		var area []netip.Prefix
		if r.Area != nil {
			area = *r.Area
		} else {
			// if no area is defined, create a new-one with only this gnb
			area = []netip.Prefix{netip.PrefixFrom(gnb_addr, 32)}
		}
		// check infos.Gnb in area
		if !gnbInArea(gnb_addr, area) {
			continue
		}
		if len(r.SegmentsList) == 0 {
			logrus.Error("Empty segments list for downlink")
			return fmt.Errorf("Empty segments list for downlink")
		}
		segList := make([]string, len(r.SegmentsList))
		copy(segList, r.SegmentsList)
		prefix, err := netip.ParsePrefix(r.SegmentsList[0])
		if err != nil {
			return err
		}
		dst := encoding.NewMGTP4IPv6Dst(prefix, gnb_addr.As4(), encoding.NewArgsMobSession(0, false, false, infos.HandoverInfos.DlTargetGnb.Teid))
		dstB, err := dst.Marshal()
		if err != nil {
			return err
		}
		dstIp, ok := netip.AddrFromSlice(dstB)
		if !ok {
			return fmt.Errorf("could not convert MGTP4IPv6Dst to netip.Addr")
		}
		// note: in srv6, segment[n] is the first segment of the path, and segment[0] is the last segment in the path
		// because Segment-Left is a pointer to the current segment and is decremented each SR-hop
		segList[0] = dstIp.String()

		srh, err := n4tosrv6.NewSRH(segList)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"segments-list": r.SegmentsList,
			}).WithError(err).Error("Creation of SRH downlink failed")
			return err
		}
		action := n4tosrv6.Action{
			SRH:        *srh,
			SourceGtp4: r.SrgwGtp4,
		}
		rule := n4tosrv6.Rule{
			Enabled: true,
			Type:    "downlink",
			Match: n4tosrv6.Match{
				Payload: &n4tosrv6.Payload{
					Dst: ue_addr,
				},
			},
			Action: action,
		}
		rule_json, err := json.Marshal(rule)
		if err != nil {
			logrus.WithError(err).Error("Could not marshal json")
			return err
		}
		wg.Add(1)
		// TODO: remove old rules
		go func() error {
			defer wg.Done()
			//infos.AnchorsLock.Lock()
			//defer infos.AnchorsLock.Unlock()
			_, _ = pusher.pushSingleRule(ctx, client, r.ControlURI, rule_json)
			// TODO: store this (after old rules are removed)
			//if err == nil {
			//	infos.AnchorsRules = append(infos.AnchorsRules, &RuleAction{
			//		Url:          url,
			//		Action:       &action,
			//		GtpDstPrefix: prefix,
			//	})
			//}
			return err
		}()

	}
	wg.Wait()
	infos.HandoverInfos = nil // reset handover state
	pusher.ues.Store(ue_ip, infos)

	return nil

}

func (pusher *RulesPusher) pushRTRRule(ctx context.Context, ue_ip string) error {
	i, ok := pusher.ues.Load(ue_ip)
	if !ok {
		return fmt.Errorf("UE not in ue list")
	}
	infos := i.(*ueInfos)
	infos.Lock()
	defer infos.Unlock()
	if infos.Pushed {
		return nil // already pushed, nothing to do
	}
	infos.Pushed = true
	logrus.WithFields(logrus.Fields{
		"ue-ip":         ue_ip,
		"gnb-ip":        infos.Gnb,
		"teid-downlink": infos.DownlinkTeid,
		"teid-uplink":   infos.UplinkFTeid.Teid,
		"addr-uplink":   infos.UplinkFTeid.Addr,
	}).Info("Pushing Router Rules")
	ue_addr, err := netip.ParseAddr(ue_ip)
	if err != nil {
		return err
	}
	gnb_addr, err := netip.ParseAddr(infos.Gnb)
	if err != nil {
		return err
	}

	client := http.Client{}
	var wg sync.WaitGroup

	for _, r := range pusher.uplink {
		if r.Service == nil {
			return fmt.Errorf("service configurated is nil for uplink rule")
		}
		//TODO: add ArgMobSession
		srh, err := n4tosrv6.NewSRH(r.SegmentsList)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"segments-list": r.SegmentsList,
			}).WithError(err).Error("Creation of SRH uplink failed")
			return err
		}
		var area []netip.Prefix
		if r.Area != nil {
			area = *r.Area
		} else {
			// if no area is defined, create a new-one with only this gnb
			area = []netip.Prefix{netip.PrefixFrom(gnb_addr, 32)}
		}
		// check infos.Gnb in area
		if !gnbInArea(gnb_addr, area) {
			continue
		}

		action := n4tosrv6.Action{
			SRH: *srh,
		}
		rule := n4tosrv6.Rule{
			Enabled: r.Enabled,
			Type:    "uplink",
			Match: n4tosrv6.Match{
				Header: &n4tosrv6.GtpHeader{
					OuterIpSrc: area,
					FTeid:      infos.UplinkFTeid,
					InnerIpSrc: &ue_addr,
				},
				Payload: &n4tosrv6.Payload{
					// TODO: allow multiple services
					Dst: *r.Service,
				},
			},
			Action: action,
		}
		rule_json, err := json.Marshal(rule)
		if err != nil {
			logrus.WithError(err).Error("Could not marshal json")
			return err
		}
		wg.Add(1)
		go func() error {
			defer wg.Done()
			infos.SRGWLock.Lock()
			defer infos.SRGWLock.Unlock()
			url, err := pusher.pushSingleRule(ctx, client, r.ControlURI, rule_json)
			if err == nil {
				infos.SRGWRules = append(infos.SRGWRules, &RuleAction{
					Url:    url,
					Action: &action,
				})
			}
			return err
		}()

	}

	for _, r := range pusher.downlink {
		var area []netip.Prefix
		if r.Area != nil {
			area = *r.Area
		} else {
			// if no area is defined, create a new-one with only this gnb
			area = []netip.Prefix{netip.PrefixFrom(gnb_addr, 32)}
		}
		// check infos.Gnb in area
		if !gnbInArea(gnb_addr, area) {
			continue
		}
		if len(r.SegmentsList) == 0 {
			logrus.Error("Empty segments list for downlink")
			return fmt.Errorf("Empty segments list for downlink")
		}
		segList := make([]string, len(r.SegmentsList))
		copy(segList, r.SegmentsList)
		prefix, err := netip.ParsePrefix(r.SegmentsList[0])
		if err != nil {
			return err
		}
		dst := encoding.NewMGTP4IPv6Dst(prefix, gnb_addr.As4(), encoding.NewArgsMobSession(0, false, false, infos.DownlinkTeid))
		dstB, err := dst.Marshal()
		if err != nil {
			return err
		}
		dstIp, ok := netip.AddrFromSlice(dstB)
		if !ok {
			return fmt.Errorf("could not convert MGTP4IPv6Dst to netip.Addr")
		}
		// note: in srv6, segment[n] is the first segment of the path, and segment[0] is the last segment in the path
		// because Segment-Left is a pointer to the current segment and is decremented each SR-hop
		segList[0] = dstIp.String()

		srh, err := n4tosrv6.NewSRH(segList)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"segments-list": r.SegmentsList,
			}).WithError(err).Error("Creation of SRH downlink failed")
			return err
		}
		action := n4tosrv6.Action{
			SRH:        *srh,
			SourceGtp4: r.SrgwGtp4,
		}
		rule := n4tosrv6.Rule{
			Enabled: true,
			Type:    "downlink",
			Match: n4tosrv6.Match{
				Payload: &n4tosrv6.Payload{
					Dst: ue_addr,
				},
			},
			Action: action,
		}
		rule_json, err := json.Marshal(rule)
		if err != nil {
			logrus.WithError(err).Error("Could not marshal json")
			return err
		}
		wg.Add(1)
		go func() error {
			defer wg.Done()
			infos.AnchorsLock.Lock()
			defer infos.AnchorsLock.Unlock()
			url, err := pusher.pushSingleRule(ctx, client, r.ControlURI, rule_json)
			if err == nil {
				infos.AnchorsRules = append(infos.AnchorsRules, &RuleAction{
					Url:          url,
					Action:       &action,
					GtpDstPrefix: prefix,
				})
			}
			return err
		}()

	}
	wg.Wait()
	pusher.ues.Store(ue_ip, infos)

	return nil
}

func (pusher *RulesPusher) pushHandover(ctx context.Context, ue_ip string, handoverTo jsonapi.Fteid) error {
	i, ok := pusher.ues.Load(ue_ip)
	if !ok {
		return fmt.Errorf("UE not in ue list")
	}
	infos := i.(*ueInfos)
	infos.Lock()
	defer infos.Unlock()

	client := http.Client{}
	var wg sync.WaitGroup

	infos.AnchorsLock.RLock()
	defer infos.AnchorsLock.RUnlock()

	logrus.WithFields(logrus.Fields{
		"nb-uplink":        len(infos.AnchorsRules),
		"ue-ip":            ue_ip,
		"handover-to-addr": handoverTo.Addr,
		"handover-to-teid": handoverTo.Teid,
	}).Debug("Pushing new downlink rules for handover")

	for _, r := range infos.AnchorsRules {
		dst := encoding.NewMGTP4IPv6Dst(r.GtpDstPrefix, handoverTo.Addr.As4(), encoding.NewArgsMobSession(0, false, false, handoverTo.Teid))
		dstB, err := dst.Marshal()
		if err != nil {
			return err
		}
		dstIp, ok := netip.AddrFromSlice(dstB)
		if !ok {
			return fmt.Errorf("could not convert MGTP4IPv6Dst to netip.Addr")
		}
		seg0, err := n4tosrv6.NewSegment(dstIp.String())
		if err != nil {
			return err
		}
		// note: in srv6, segment[n] is the first segment of the path, and segment[0] is the last segment in the path
		// because Segment-Left is a pointer to the current segment and is decremented each SR-hop
		r.Action.SRH[0] = seg0

		action_json, err := json.Marshal(r.Action)
		if err != nil {
			logrus.WithError(err).Error("Could not marshal json")
			return err
		}
		wg.Add(1)
		go func() error {
			defer wg.Done()
			err := pusher.pushUpdateAction(ctx, client, r.Url.JoinPath("update-action"), action_json)
			if err != nil {
				logrus.WithError(err).Error("Could not push update action")
			} else {
				logrus.WithFields(logrus.Fields{
					"path": r.Url.JoinPath("update-action").String(),
				}).Debug("pushed update action")
			}
			return err
		}()
	}
	wg.Wait()
	infos.Gnb = handoverTo.Addr.String()
	infos.DownlinkTeid = handoverTo.Teid
	pusher.ues.Store(ue_ip, infos)
	return nil

}

func (pusher *RulesPusher) updateRoutersRules(ctx context.Context, msgType pfcputil.MessageType, msg pfcp_networking.ReceivedMessage, e *pfcp_networking.PFCPEntityUP) {
	logrus.Debug("Into updateRoutersRules")
	if msgType == message.MsgTypeSessionModificationRequest {
		logrus.Debug("session modification request")
		// check if handover
		msgMod, ok := msg.Message.(*message.SessionModificationRequest)
		if !ok {
			logrus.Error("could not cast to sessionModifationRequest")
			return
		}

		// detect handover with direct forwarding
		logrus.Debug("checking session modification request for handover")
		if (len(msgMod.CreatePDR) == 0) && (len(msgMod.UpdatePDR) == 0) && (len(msgMod.CreateFAR) == 0) && (len(msgMod.UpdateFAR) == 1) {
			// this is only a far update, so it is probably an handover…
			updateFpIes, err := msgMod.UpdateFAR[0].UpdateForwardingParameters()
			if err != nil {
				logrus.WithError(err).Debug("No Update Forwarding parameters: not a valid handover")
				return
			}
			updateFp := ie.NewUpdateForwardingParameters(updateFpIes...)

			if dest_interface, err := updateFp.DestinationInterface(); err != nil {
				logrus.Debug("No destination interface: not a valid handover")
				return
			} else if dest_interface != ie.DstInterfaceAccess {
				logrus.Debug("Destination interface is not access: not a valid handover")
				return
			}
			farid, err := msgMod.UpdateFAR[0].FARID()
			if err != nil {
				logrus.Debug("No FARID: not a valid handover")
				return
			}
			logrus.WithFields(logrus.Fields{
				"farid": farid,
			}).Debug("handover detected")

			ohc, err := updateFp.OuterHeaderCreation()
			if err != nil {
				return
			}
			addr, ok := netip.AddrFromSlice(ohc.IPv4Address.To4())
			if !ok {
				return
			}
			handoverTo := jsonapi.Fteid{
				Teid: ohc.TEID,
				Addr: addr,
			}

			handoverDone := false
			// looking for a pdr with this farid to find ue ip address
			for _, session := range e.GetPFCPSessions() {
				if handoverDone {
					break
				}
				s := make(chan struct{})
				go func() { // in a goroutine to trigger the defer
					session.RLock()
					defer session.RUnlock()
					session.ForeachUnsortedPDR(func(pdr pfcpapi.PDRInterface) error {
						id, err := pdr.FARID()
						if err != nil {
							// skip
							return nil
						}
						if id != farid {
							// skip
							return nil
						}
						pdrid, err := pdr.ID()
						if err != nil {
							return nil
						}
						ue, err := pdr.UEIPAddress()
						if err != nil {
							return nil
						}
						logrus.WithFields(logrus.Fields{
							"farid": farid,
							"pdrid": pdrid,
							"ue":    ue.IPv4Address.String(),
						}).Debug("UE identified for handover")
						go func() {
							err := pusher.pushHandover(ctx, ue.IPv4Address.String(), handoverTo)
							if err != nil {
								logrus.WithError(err).Error("Could not push handover rule")
							}
						}()
						handoverDone = true
						return nil
					})
					s <- struct{}{}
				}()
				<-s
			}
			return
		}
	}
	var wg0 sync.WaitGroup
	for _, session := range e.GetPFCPSessions() {
		logrus.Trace("In for loop…")
		wg0.Add(1)
		go func() error {
			defer wg0.Done()
			session.RLock()
			defer session.RUnlock()
			session.ForeachUnsortedPDR(func(pdr pfcpapi.PDRInterface) error {
				farid, err := pdr.FARID()
				if err != nil {
					logrus.WithError(err).Debug("skip: error getting FARid")
					return nil
				}
				ue_ip_addr, err := pdr.UEIPAddress()
				if err != nil {
					logrus.WithError(err).Debug("skip: error getting ueipaddr")
					return nil
				}

				// FIXME: temporary hack, no IPv6 support
				ue_ipv4 := ue_ip_addr.IPv4Address.String()
				if source_iface, err := pdr.SourceInterface(); err != nil {
					logrus.WithError(err).Debug("skip: error getting source-iface")
					return nil
				} else if source_iface == ie.SrcInterfaceAccess {
					fteid, err := pdr.FTEID()
					if err != nil {
						logrus.WithError(err).Debug("skip: no fteid")
						return nil
					}
					addr, ok := netip.AddrFromSlice(fteid.IPv4Address.To4())
					if !ok {
						logrus.WithError(err).Debug("skip: could not parse uplink fteid addr")
						return nil
					}
					if ue, loaded := pusher.ues.LoadOrStore(ue_ipv4, &ueInfos{
						UplinkFTeid:  jsonapi.Fteid{Teid: fteid.TEID, Addr: addr},
						AnchorsRules: make([]*RuleAction, 0),
						SRGWRules:    make([]*RuleAction, 0),
					}); loaded {
						if ue.(*ueInfos).Pushed {
							if addr == ue.(*ueInfos).UplinkFTeid.Addr && fteid.TEID == ue.(*ueInfos).UplinkFTeid.Teid {
								return nil // old data
							}
							logrus.WithFields(logrus.Fields{
								"teid-uplink": fteid.TEID,
								"addr-uplink": addr,
								"ue-ipv4":     ue_ipv4,
							}).Debug("Updating UeInfos with handoverInfos for uplink")
							ue.(*ueInfos).Lock()
							ue.(*ueInfos).HandoverInfos = &HandoverInfos{
								UlTargetSrgw: jsonapi.Fteid{Teid: fteid.TEID, Addr: addr},
							}
							ue.(*ueInfos).Unlock()

						} else {
							logrus.WithFields(logrus.Fields{
								"teid-uplink": fteid.TEID,
								"ue-ipv4":     ue_ipv4,
							}).Debug("Updating UeInfos")

							ue.(*ueInfos).Lock()
							ue.(*ueInfos).UplinkFTeid = jsonapi.Fteid{Teid: fteid.TEID, Addr: addr}
							ue.(*ueInfos).Unlock()
						}
					} else if logrus.IsLevelEnabled(logrus.DebugLevel) {
						logrus.WithFields(logrus.Fields{
							"teid-uplink": fteid.TEID,
							"ue-ipv4":     ue_ipv4,
						}).Debug("Adding new ue to UeInfos")
					}

				} else if (source_iface == ie.SrcInterfaceCore) || (source_iface == ie.SrcInterfaceSGiLANN6LAN) {
					far, err := session.GetFAR(farid)
					if err != nil {
						logrus.WithError(err).Debug("skip: error getting far")
						return nil
					}
					ForwardingParametersIe, err := far.ForwardingParameters()
					if err != nil {
						// no forwarding prameters (maybe because hasn't FORW ?)
						return nil
					}
					if ohc, err := ForwardingParametersIe.OuterHeaderCreation(); err == nil {
						// FIXME: temporary hack, no IPv6 support
						gnb_ipv4 := ohc.IPv4Address.String()
						teid_downlink := ohc.TEID
						if ue, loaded := pusher.ues.LoadOrStore(ue_ipv4, &ueInfos{
							DownlinkTeid: teid_downlink,
							Gnb:          gnb_ipv4,
							AnchorsRules: make([]*RuleAction, 0),
							SRGWRules:    make([]*RuleAction, 0),
						}); loaded {
							if ue.(*ueInfos).Pushed {
								if gnb_ipv4 == ue.(*ueInfos).Gnb && teid_downlink == ue.(*ueInfos).DownlinkTeid {
									return nil // old info
								}
								addr, err := netip.ParseAddr(gnb_ipv4)
								if err != nil {
									return nil
								}
								logrus.WithFields(logrus.Fields{
									"teid-downlink": teid_downlink,
									"addr-downlink": gnb_ipv4,
									"ue-ipv4":       ue_ipv4,
								}).Debug("Updating UeInfos with handoverInfos for downlink")
								ue.(*ueInfos).Lock()
								ue.(*ueInfos).HandoverInfos.DlTargetGnb = &jsonapi.Fteid{Teid: teid_downlink, Addr: addr}
								ue.(*ueInfos).Unlock()
							} else {
								logrus.WithFields(logrus.Fields{
									"gnb-ipv4":      gnb_ipv4,
									"teid-downlink": teid_downlink,
									"ue-ipv4":       ue_ipv4,
								}).Debug("Updating UeInfos")
								ue.(*ueInfos).Lock()
								ue.(*ueInfos).Gnb = gnb_ipv4
								ue.(*ueInfos).DownlinkTeid = teid_downlink
								ue.(*ueInfos).Unlock()
							}
						} else if logrus.IsLevelEnabled(logrus.DebugLevel) {
							logrus.WithFields(logrus.Fields{
								"gnb-ipv4":      gnb_ipv4,
								"teid-downlink": teid_downlink,
								"ue-ipv4":       ue_ipv4,
							}).Debug("Adding new ue to UeInfos")
						}

					} else {
						logrus.WithError(err).Debug("skip: error getting ohc")
						return nil
					}
				} else {
					return nil
				}
				return nil
			})
			return nil
		}()
	}
	wg0.Wait()
	var wg sync.WaitGroup
	pusher.ues.Range(func(ip any, ue any) bool {
		if ue.(*ueInfos).DownlinkTeid == 0 {
			// no set yet => session will be modified
			logrus.WithFields(logrus.Fields{
				"ue-ipv4": ip,
			}).Debug("Downlink TEID is null")
			return true
		}
		logrus.WithFields(logrus.Fields{
			"ue-ipv4":       ip,
			"gnb-ipv4":      ue.(*ueInfos).Gnb,
			"teid-downlink": ue.(*ueInfos).DownlinkTeid,
			"teid-uplink":   ue.(*ueInfos).UplinkFTeid.Teid,
			"addr-uplink":   ue.(*ueInfos).UplinkFTeid.Addr,
		}).Debug("PushRTRRule")
		wg.Add(1)
		go func() {
			defer wg.Done()
			pusher.pushRTRRule(ctx, ip.(string))
			pusher.pushHandoverAcrossAreas(ctx, ip.(string))
			// TODO: check pushRTRRule return code and send pfcp error on failure
		}()
		return true
	})
	wg.Wait()
	logrus.Debug("Exit updateRoutersRules")
}
