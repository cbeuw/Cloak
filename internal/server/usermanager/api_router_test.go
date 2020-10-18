package usermanager

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

var mockUIDb64 = base64.StdEncoding.EncodeToString(mockUID)

func makeRouter(t *testing.T) (router *APIRouter, cleaner func()) {
	var tmpDB, _ = ioutil.TempFile("", "ck_user_info")
	cleaner = func() { os.Remove(tmpDB.Name()) }
	mgr, err := MakeLocalManager(tmpDB.Name(), mockWorldState)
	if err != nil {
		t.Fatal(err)
	}
	router = APIRouterOf(mgr)
	return router, cleaner
}

func TestWriteUserInfoHlr(t *testing.T) {
	router, cleaner := makeRouter(t)
	defer cleaner()
	rr := httptest.NewRecorder()

	marshalled, err := json.Marshal(mockUserInfo)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/admin/users/"+mockUIDb64, bytes.NewBuffer(marshalled))
	if err != nil {
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("handler returned wrong status code: got %v with body %v, want %v",
			status, rr.Body, http.StatusCreated)
	}
}
