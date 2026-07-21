package snetutils

import (
	"net"
	"testing"
)

func TestIpBetween(t *testing.T) {
	tests := []struct {
		name     string
		from, to string
		test     string
		want     bool
	}{
		{"in range", "10.0.0.1", "10.0.0.10", "10.0.0.5", true},
		{"at start", "10.0.0.1", "10.0.0.10", "10.0.0.1", true},
		{"at end", "10.0.0.1", "10.0.0.10", "10.0.0.10", true},
		{"before range", "10.0.0.5", "10.0.0.10", "10.0.0.1", false},
		{"after range", "10.0.0.1", "10.0.0.5", "10.0.0.10", false},
		{"different subnet", "192.168.1.1", "192.168.1.254", "10.0.0.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IpBetween(net.ParseIP(tt.from), net.ParseIP(tt.to), net.ParseIP(tt.test))
			if got != tt.want {
				t.Errorf("IpBetween(%s, %s, %s) = %v, want %v", tt.from, tt.to, tt.test, got, tt.want)
			}
		})
	}
}

func TestIpBetween_Nil(t *testing.T) {
	if IpBetween(nil, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.5")) {
		t.Error("expected false for nil from")
	}
}

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"public", "8.8.8.8", true},
		{"private 10.x", "10.0.0.1", false},
		{"private 192.168.x", "192.168.1.1", false},
		{"private 172.16.x", "172.16.0.1", false},
		{"loopback", "127.0.0.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsPublicIP(net.ParseIP(tt.ip))
			if got != tt.want {
				t.Errorf("IsPublicIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsPublicIP_Nil(t *testing.T) {
	if IsPublicIP(nil) {
		t.Error("expected false for nil IP")
	}
}

func TestIpInc(t *testing.T) {
	ip := net.ParseIP("192.168.1.1").To4()
	IpInc(ip)
	expected := "192.168.1.2"
	if ip.String() != expected {
		t.Errorf("IpInc: got %s, want %s", ip.String(), expected)
	}

	// Test rollover
	ip2 := net.ParseIP("192.168.1.255").To4()
	IpInc(ip2)
	expected2 := "192.168.2.0"
	if ip2.String() != expected2 {
		t.Errorf("IpInc rollover: got %s, want %s", ip2.String(), expected2)
	}
}

func TestIpIsPrivate(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"10.x", "10.0.0.1", true},
		{"10.255", "10.255.255.255", true},
		{"192.168.x", "192.168.1.100", true},
		{"172.16.x", "172.16.0.1", true},
		{"172.31.x", "172.31.255.255", true},
		{"127.x", "127.0.0.1", true},
		{"public", "8.8.8.8", false},
		{"public 1.1.1.1", "1.1.1.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IpIsPrivate(tt.ip)
			if got != tt.want {
				t.Errorf("IpIsPrivate(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIpParserCIDR(t *testing.T) {
	mask, gw, err := IpParserCIDR("192.168.1.100/24")
	if err != nil {
		t.Fatalf("IpParserCIDR failed: %v", err)
	}
	if mask != "255.255.255.0" {
		t.Errorf("mask = %s, want 255.255.255.0", mask)
	}
	if gw != "192.168.1.1" {
		t.Errorf("gateway = %s, want 192.168.1.1", gw)
	}
}

func TestIpParserCIDR_16(t *testing.T) {
	mask, gw, err := IpParserCIDR("10.0.5.100/16")
	if err != nil {
		t.Fatalf("IpParserCIDR failed: %v", err)
	}
	if mask != "255.255.0.0" {
		t.Errorf("mask = %s, want 255.255.0.0", mask)
	}
	if gw != "10.0.0.1" {
		t.Errorf("gateway = %s, want 10.0.0.1", gw)
	}
}

func TestIpParserCIDR_Invalid(t *testing.T) {
	_, _, err := IpParserCIDR("not-a-cidr")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestIpGetDefault(t *testing.T) {
	mask, gw, err := IpGetDefault("10.5.3.100")
	if err != nil {
		t.Fatalf("IpGetDefault failed: %v", err)
	}
	// Class A: default mask 255.0.0.0, gw 10.0.0.1
	if mask != "255.0.0.0" {
		t.Errorf("mask = %s, want 255.0.0.0", mask)
	}
	if gw != "10.0.0.1" {
		t.Errorf("gateway = %s, want 10.0.0.1", gw)
	}
}

func TestGetFreePort(t *testing.T) {
	port, err := GetFreePort()
	if err != nil {
		t.Fatalf("GetFreePort failed: %v", err)
	}
	if port <= 0 || port > 65535 {
		t.Errorf("invalid port: %d", port)
	}
}

func TestGetFreePorts(t *testing.T) {
	ports, err := GetFreePorts(3)
	if err != nil {
		t.Fatalf("GetFreePorts failed: %v", err)
	}
	if len(ports) != 3 {
		t.Errorf("expected 3 ports, got %d", len(ports))
	}
	// All ports should be unique
	seen := make(map[int]bool)
	for _, p := range ports {
		if p <= 0 || p > 65535 {
			t.Errorf("invalid port: %d", p)
		}
		if seen[p] {
			t.Errorf("duplicate port: %d", p)
		}
		seen[p] = true
	}
}
