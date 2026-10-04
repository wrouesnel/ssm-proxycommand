package fakeaws

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
)

// Instance is a fake EC2 instance.
type Instance struct {
	ID        string
	State     string
	PrivateIP string
	PublicIP  string
	Tags      map[string]string
}

// StartedSession records an ssm:StartSession call.
type StartedSession struct {
	SessionID    string
	Target       string
	DocumentName string
	Parameters   map[string][]string
}

// API serves just enough of EC2 DescribeInstances and SSM StartSession, ResumeSession and
// TerminateSession for the CLI to run against it via AWS_ENDPOINT_URL. Each started session
// gets its own Agent forwarding to Target.
type API struct {
	Instances []Instance
	Target    string

	srv *httptest.Server

	mu         sync.Mutex
	agents     map[string]*Agent
	started    []StartedSession
	terminated []string
}

// Start begins serving and returns the endpoint URL.
func (f *API) Start() string {
	f.agents = map[string]*Agent{}
	f.srv = httptest.NewServer(f)
	return f.srv.URL
}

// Close stops the API and every agent it started.
func (f *API) Close() {
	f.srv.Close()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.agents {
		a.Close()
	}
}

// Started returns the sessions started so far.
func (f *API) Started() []StartedSession {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.started)
}

// Terminated returns the IDs of sessions terminated through the API.
func (f *API) Terminated() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.terminated)
}

// AgentErrors collects protocol errors from every agent.
func (f *API) AgentErrors() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for id, a := range f.agents {
		for _, e := range a.Errors() {
			out = append(out, id+": "+e)
		}
	}
	return out
}

func (f *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		http.Error(w, "unsigned request", http.StatusForbidden)
		return
	}
	if target := r.Header.Get("X-Amz-Target"); strings.HasPrefix(target, "AmazonSSM.") {
		f.serveSSM(w, r, strings.TrimPrefix(target, "AmazonSSM."))
		return
	}
	if err := r.ParseForm(); err != nil || r.Form.Get("Action") != "DescribeInstances" {
		http.Error(w, "unsupported", http.StatusBadRequest)
		return
	}
	f.describeInstances(w, r)
}

func (f *API) serveSSM(w http.ResponseWriter, r *http.Request, op string) {
	body, _ := io.ReadAll(r.Body)
	var req map[string]any
	_ = json.Unmarshal(body, &req)
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")

	f.mu.Lock()
	defer f.mu.Unlock()
	switch op {
	case "StartSession":
		id := fmt.Sprintf("sess-%d", len(f.started)+1)
		var params map[string][]string
		if p, ok := req["Parameters"]; ok {
			b, _ := json.Marshal(p)
			_ = json.Unmarshal(b, &params)
		}
		target, _ := req["Target"].(string)
		doc, _ := req["DocumentName"].(string)
		f.started = append(f.started, StartedSession{SessionID: id, Target: target, DocumentName: doc, Parameters: params})
		a := NewAgent(f.Target)
		a.Start()
		f.agents[id] = a
		_ = json.NewEncoder(w).Encode(map[string]string{"SessionId": id, "StreamUrl": a.URL(), "TokenValue": InitialToken})
	case "ResumeSession":
		id, _ := req["SessionId"].(string)
		a, ok := f.agents[id]
		if !ok {
			http.Error(w, `{"__type":"DoesNotExistException","message":"no session"}`, http.StatusBadRequest)
			return
		}
		tok, _, _ := a.Resume(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]string{"SessionId": id, "StreamUrl": a.URL(), "TokenValue": tok})
	case "TerminateSession":
		id, _ := req["SessionId"].(string)
		f.terminated = append(f.terminated, id)
		_ = json.NewEncoder(w).Encode(map[string]string{"SessionId": id})
	default:
		http.Error(w, `{"__type":"InvalidAction","message":"unsupported"}`, http.StatusBadRequest)
	}
}

type ec2Tag struct {
	Key   string `xml:"key"`
	Value string `xml:"value"`
}

type ec2Instance struct {
	InstanceID       string   `xml:"instanceId"`
	State            string   `xml:"instanceState>name"`
	PrivateIP        string   `xml:"privateIpAddress,omitempty"`
	PrivateDNS       string   `xml:"privateDnsName,omitempty"`
	PublicIP         string   `xml:"ipAddress,omitempty"`
	Tags             []ec2Tag `xml:"tagSet>item"`
	NetworkInterface []struct {
		PrivateIPs []struct {
			PrivateIP string `xml:"privateIpAddress"`
		} `xml:"privateIpAddressesSet>item"`
	} `xml:"networkInterfaceSet>item"`
}

type describeInstancesResponse struct {
	XMLName      xml.Name      `xml:"DescribeInstancesResponse"`
	Xmlns        string        `xml:"xmlns,attr"`
	RequestID    string        `xml:"requestId"`
	Reservations []ec2Instance `xml:"reservationSet>item>instancesSet>item"`
}

// describeInstances honours the filters the resolver uses.
func (f *API) describeInstances(w http.ResponseWriter, r *http.Request) {
	filters := map[string][]string{}
	for i := 1; ; i++ {
		name := r.Form.Get(fmt.Sprintf("Filter.%d.Name", i))
		if name == "" {
			break
		}
		for j := 1; ; j++ {
			v := r.Form.Get(fmt.Sprintf("Filter.%d.Value.%d", i, j))
			if v == "" {
				break
			}
			filters[name] = append(filters[name], v)
		}
	}

	resp := describeInstancesResponse{Xmlns: "http://ec2.amazonaws.com/doc/2016-11-15/", RequestID: "req-1"}
	for _, inst := range f.Instances {
		privDNS := "ip-" + strings.ReplaceAll(inst.PrivateIP, ".", "-") + ".ec2.internal"
		var tagKeys []string
		for k := range inst.Tags {
			tagKeys = append(tagKeys, k)
		}
		have := map[string][]string{
			"instance-state-name":                            {inst.State},
			"network-interface.addresses.private-ip-address": {inst.PrivateIP},
			"ip-address":       {inst.PublicIP},
			"private-dns-name": {privDNS},
			"dns-name":         {},
			"tag-key":          tagKeys,
		}
		ok := true
		for name, values := range filters {
			if !slices.ContainsFunc(have[name], func(h string) bool { return slices.Contains(values, h) }) {
				ok = false
			}
		}
		if !ok {
			continue
		}
		ei := ec2Instance{InstanceID: inst.ID, State: inst.State, PrivateIP: inst.PrivateIP, PrivateDNS: privDNS, PublicIP: inst.PublicIP}
		for k, v := range inst.Tags {
			ei.Tags = append(ei.Tags, ec2Tag{Key: k, Value: v})
		}
		resp.Reservations = append(resp.Reservations, ei)
	}
	w.Header().Set("Content-Type", "text/xml")
	_ = xml.NewEncoder(w).Encode(resp)
}
