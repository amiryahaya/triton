//go:build integration

package manageserver_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDebug_Refresh(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	user := seedAdminUser(t, store)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	oldToken := loginViaHTTP(t, ts.URL, user.Email, "Password123!")
	fmt.Println("Old token:", oldToken[:20], "...")

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+oldToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println("Status:", resp.StatusCode)
	fmt.Println("Body:", string(body))

	var out map[string]any
	_ = json.NewDecoder(strings.NewReader(string(body))).Decode(&out)
	t.Logf("refresh response: %v", out)
}
