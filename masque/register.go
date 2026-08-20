package masque

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	apiURL     = "https://api.cloudflareclient.com"
	apiVersion = "v0a4471"
	configName = "config.json"
)

var cfHeaders = map[string]string{
	"User-Agent":        "WARP for Android",
	"CF-Client-Version": "a-6.35-4471",
	"Content-Type":      "application/json; charset=UTF-8",
	"Connection":        "Keep-Alive",
}

type registration struct {
	Key       string `json:"key"`
	InstallID string `json:"install_id"`
	FcmToken  string `json:"fcm_token"`
	Tos       string `json:"tos"`
	Model     string `json:"model"`
	Serial    string `json:"serial_number"`
	OsVersion string `json:"os_version"`
	KeyType   string `json:"key_type"`
	TunType   string `json:"tunnel_type"`
	Locale    string `json:"locale"`
}

type accountData struct {
	ID      string `json:"id"`
	Token   string `json:"token,omitempty"`
	Account struct {
		License string `json:"license"`
	} `json:"account"`
	Config struct {
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

type deviceUpdate struct {
	Key     string `json:"key"`
	KeyType string `json:"key_type"`
	TunType string `json:"tunnel_type"`
	Name    string `json:"name,omitempty"`
}

// EnsureIdentity loads or creates a MASQUE identity under dir.
func EnsureIdentity(dir string) (*Config, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, configName)
	if _, err := os.Stat(path); err == nil {
		return LoadConfig(path)
	}

	log.Println("Registering Cloudflare MASQUE identity (first run) ...")
	cfg, err := registerAndEnroll()
	if err != nil {
		return nil, err
	}
	if err := cfg.Save(path); err != nil {
		return nil, err
	}
	log.Printf("MASQUE config saved to %s", path)
	return cfg, nil
}

func registerAndEnroll() (*Config, error) {
	wgKey := make([]byte, 32)
	if _, err := rand.Read(wgKey); err != nil {
		return nil, err
	}
	serial := make([]byte, 8)
	if _, err := rand.Read(serial); err != nil {
		return nil, err
	}

	reg := registration{
		Key:     base64.StdEncoding.EncodeToString(wgKey),
		Tos:     time.Now().UTC().Format("2006-01-02T15:04:05.000-07:00"),
		Model:   "PC",
		Serial:  strings.ToLower(hex.EncodeToString(serial)),
		KeyType: "curve25519",
		TunType: "wireguard",
		Locale:  "en_US",
	}
	body, _ := json.Marshal(reg)
	req, err := http.NewRequest(http.MethodPost, apiURL+"/"+apiVersion+"/reg", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range cfHeaders {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("register failed: %s %s", resp.Status, string(raw))
	}
	var account accountData
	if err := json.Unmarshal(raw, &account); err != nil {
		return nil, err
	}

	privKey, pubKey, err := generateEcKeyPair()
	if err != nil {
		return nil, err
	}

	upd := deviceUpdate{
		Key:     base64.StdEncoding.EncodeToString(pubKey),
		KeyType: "secp256r1",
		TunType: "masque",
		Name:    "CustomPsiphon",
	}
	body, _ = json.Marshal(upd)
	req, err = http.NewRequest(http.MethodPatch, apiURL+"/"+apiVersion+"/reg/"+account.ID, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range cfHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+account.Token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enroll failed: %s %s", resp.Status, string(raw))
	}
	if err := json.Unmarshal(raw, &account); err != nil {
		return nil, err
	}
	if len(account.Config.Peers) == 0 {
		return nil, fmt.Errorf("enroll response missing peers")
	}

	peer := account.Config.Peers[0]
	endpointV4 := strings.TrimSuffix(peer.Endpoint.V4, ":0")
	endpointV6 := peer.Endpoint.V6
	if strings.HasPrefix(endpointV6, "[") && strings.HasSuffix(endpointV6, "]:0") {
		endpointV6 = endpointV6[1 : len(endpointV6)-3]
	}

	return &Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(privKey),
		EndpointV4:     endpointV4,
		EndpointV6:     endpointV6,
		EndpointPubKey: peer.PublicKey,
		License:        account.Account.License,
		ID:             account.ID,
		AccessToken:    account.Token,
		IPv4:           account.Config.Interface.Addresses.V4,
		IPv6:           account.Config.Interface.Addresses.V6,
		EndpointH2V4:   defaultH2Endpoint,
	}, nil
}
