/*
 *
 * k6 - a next-generation load testing tool
 * Copyright (C) 2016 Load Impact
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package netext

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	"github.com/loadimpact/resolvent"
	resq "github.com/loadimpact/resolvent/querier/network"
	"github.com/miekg/dns"

	"github.com/loadimpact/k6/lib"
	"github.com/loadimpact/k6/lib/metrics"
	"github.com/loadimpact/k6/stats"
)

// Dialer wraps net.Dialer and provides k6 specific functionality -
// tracing, blacklists and DNS cache and aliases.
type Dialer struct {
	net.Dialer

	Resolver  resolvent.Querier
	Blacklist []*lib.IPNet
	Hosts     map[string]net.IP

	BytesRead    int64
	BytesWritten int64
}

// NewDialer constructs a new Dialer and initializes its cache.
func NewDialer(dialer net.Dialer, blacklist []*lib.IPNet, hosts map[string]net.IP) (*Dialer, error) {
	var (
		q   resolvent.Querier
		err error
	)
	if q, err = resq.New(); err != nil {
		return nil, err
	}
	return &Dialer{
		Dialer:    dialer,
		Resolver:  q,
		Blacklist: blacklist,
		Hosts:     hosts,
	}, nil
}

// BlackListedIPError is an error that is returned when a given IP is blacklisted
type BlackListedIPError struct {
	ip  net.IP
	net *lib.IPNet
}

func (b BlackListedIPError) Error() string {
	return fmt.Sprintf("IP (%s) is in a blacklisted range (%s)", b.ip, b.net)
}

// DialContext wraps the net.Dialer.DialContext and handles the k6 specifics
func (d *Dialer) DialContext(ctx context.Context, proto, addr string) (net.Conn, error) {
	address, err := d.checkAndResolveAddress(ctx, addr, d.Resolver)
	if err != nil {
		return nil, err
	}

	var conn net.Conn
	conn, err = d.Dialer.DialContext(ctx, proto, address)
	if err != nil {
		return nil, err
	}
	conn = &Conn{conn, &d.BytesRead, &d.BytesWritten}
	return conn, err
}

func (d *Dialer) checkAndResolveAddress(
	ctx context.Context, addr string, resolver resolvent.Querier,
) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// It's not an IP address, so lookup the hostname in the Hosts
		// option before trying to resolve DNS.
		var ok bool
		ip, ok = d.Hosts[host]
		if !ok {
			var dnsErr error
			ips, dnsErr := d.resolve(ctx, host)
			if dnsErr != nil {
				return "", dnsErr
			}
			// TODO: Round-robin?
			ip = ips[rand.Intn(len(ips))]
		}
	}

	for _, ipnet := range d.Blacklist {
		if (*net.IPNet)(ipnet).Contains(ip) {
			return "", BlackListedIPError{ip: ip, net: ipnet}
		}
	}

	return net.JoinHostPort(ip.String(), port), nil
}

func (d *Dialer) resolve(ctx context.Context, host string) ([]net.IP, error) {
	// TODO: Check /etc/{nsswitch.conf,hosts} first?
	// TODO: Handle IPv6 AAAA records, CNAMEs...
	response, _, err := d.Resolver.Query(
		ctx,
		resolvent.TCP,
		net.IPv4zero,
		// TODO: Check /etc/resolv.conf ? See miekg/dns.ClientConfigFromFile()
		net.ParseIP("127.0.0.1"),
		53,
		host,
		dns.ClassINET,
		dns.TypeA,
	)
	if err != nil {
		return nil, err
	}
	if len(response.Answer) == 0 {
		return nil, fmt.Errorf("DNS lookup for '%s' returned zero entries", host)
	}

	ips := make([]net.IP, 0, len(response.Answer))
	for _, ans := range response.Answer {
		switch a := ans.(type) {
		case *dns.A:
			ips = append(ips, a.A)
		case *dns.AAAA:
			ips = append(ips, a.AAAA)
		}
	}

	return ips, nil
}

// GetTrail creates a new NetTrail instance with the Dialer
// sent and received data metrics and the supplied times and tags.
// TODO: Refactor this according to
// https://github.com/loadimpact/k6/pull/1203#discussion_r337938370
func (d *Dialer) GetTrail(
	startTime, endTime time.Time, fullIteration bool, emitIterations bool, tags *stats.SampleTags,
) *NetTrail {
	bytesWritten := atomic.SwapInt64(&d.BytesWritten, 0)
	bytesRead := atomic.SwapInt64(&d.BytesRead, 0)
	samples := []stats.Sample{
		{
			Time:   endTime,
			Metric: metrics.DataSent,
			Value:  float64(bytesWritten),
			Tags:   tags,
		},
		{
			Time:   endTime,
			Metric: metrics.DataReceived,
			Value:  float64(bytesRead),
			Tags:   tags,
		},
	}
	if fullIteration {
		samples = append(samples, stats.Sample{
			Time:   endTime,
			Metric: metrics.IterationDuration,
			Value:  stats.D(endTime.Sub(startTime)),
			Tags:   tags,
		})
		if emitIterations {
			samples = append(samples, stats.Sample{
				Time:   endTime,
				Metric: metrics.Iterations,
				Value:  1,
				Tags:   tags,
			})
		}
	}

	return &NetTrail{
		BytesRead:     bytesRead,
		BytesWritten:  bytesWritten,
		FullIteration: fullIteration,
		StartTime:     startTime,
		EndTime:       endTime,
		Tags:          tags,
		Samples:       samples,
	}
}

// NetTrail contains information about the exchanged data size and length of a
// series of connections from a particular netext.Dialer
type NetTrail struct {
	BytesRead     int64
	BytesWritten  int64
	FullIteration bool
	StartTime     time.Time
	EndTime       time.Time
	Tags          *stats.SampleTags
	Samples       []stats.Sample
}

// Ensure that interfaces are implemented correctly
var _ stats.ConnectedSampleContainer = &NetTrail{}

// GetSamples implements the stats.SampleContainer interface.
func (ntr *NetTrail) GetSamples() []stats.Sample {
	return ntr.Samples
}

// GetTags implements the stats.ConnectedSampleContainer interface.
func (ntr *NetTrail) GetTags() *stats.SampleTags {
	return ntr.Tags
}

// GetTime implements the stats.ConnectedSampleContainer interface.
func (ntr *NetTrail) GetTime() time.Time {
	return ntr.EndTime
}

// Conn wraps net.Conn and keeps track of sent and received data size
type Conn struct {
	net.Conn

	BytesRead, BytesWritten *int64
}

func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		atomic.AddInt64(c.BytesRead, int64(n))
	}
	return n, err
}

func (c *Conn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		atomic.AddInt64(c.BytesWritten, int64(n))
	}
	return n, err
}

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}
