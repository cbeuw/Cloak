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

	"github.com/stretchr/testify/assert"
)

var mockUIDb64 = base64.URLEncoding.EncodeToString(mockUID)

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

	marshalled, err := json.Marshal(mockUserInfo)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("ok", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/admin/users/"+mockUIDb64, bytes.NewBuffer(marshalled))
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equalf(t, http.StatusCreated, rr.Code, "response body: %v", rr.Body)
	})

	t.Run("partial update", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/admin/users/"+mockUIDb64, bytes.NewBuffer(marshalled))
		assert.NoError(t, err)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusCreated, rr.Code)

		partialUserInfo := UserInfo{
			UID:         mockUID,
			SessionsCap: JustInt32(10),
		}
		partialMarshalled, _ := json.Marshal(partialUserInfo)
		req, err = http.NewRequest("POST", "/admin/users/"+mockUIDb64, bytes.NewBuffer(partialMarshalled))
		assert.NoError(t, err)
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusCreated, rr.Code)

		req, err = http.NewRequest("GET", "/admin/users/"+mockUIDb64, nil)
		assert.NoError(t, err)
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusCreated, rr.Code)
		var got UserInfo
		err = json.Unmarshal(rr.Body.Bytes(), &got)
		assert.NoError(t, err)

		expected := mockUserInfo
		expected.SessionsCap = partialUserInfo.SessionsCap
		assert.EqualValues(t, expected, got)
	})

	t.Run("empty parameter", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/admin/users/", bytes.NewBuffer(marshalled))
		if err != nil {
			t.Fatal(err)
		}
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equalf(t, http.StatusMethodNotAllowed, rr.Code, "response body: %v", rr.Body)
	})

	t.Run("UID mismatch", func(t *testing.T) {
		badMock := mockUserInfo
		badMock.UID = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0}
		badMarshal, err := json.Marshal(badMock)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest("POST", "/admin/users/"+mockUIDb64, bytes.NewBuffer(badMarshal))
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equalf(t, http.StatusBadRequest, rr.Code, "response body: %v", rr.Body)
	})

	t.Run("garbage data", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/admin/users/"+mockUIDb64, bytes.NewBuffer([]byte(`{"{{'{;;}}}1`)))
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equalf(t, http.StatusBadRequest, rr.Code, "response body: %v", rr.Body)
	})

	t.Run("not base64", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/admin/users/"+"defonotbase64", bytes.NewBuffer(marshalled))
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equalf(t, http.StatusBadRequest, rr.Code, "response body: %v", rr.Body)
	})
}

func addUser(t *testing.T, router *APIRouter, user UserInfo) {
	marshalled, err := json.Marshal(user)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", "/admin/users/"+base64.URLEncoding.EncodeToString(user.UID), bytes.NewBuffer(marshalled))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equalf(t, http.StatusCreated, rr.Code, "response body: %v", rr.Body)
}

func TestGetUserInfoHlr(t *testing.T) {
	router, cleaner := makeRouter(t)
	defer cleaner()

	t.Run("empty parameter", func(t *testing.T) {
		assert.HTTPError(t, router.ServeHTTP, "GET", "/admin/users/", nil)
	})

	t.Run("non-existent", func(t *testing.T) {
		assert.HTTPError(t, router.ServeHTTP, "GET", "/admin/users/"+base64.URLEncoding.EncodeToString([]byte("adsf")), nil)
	})

	t.Run("not base64", func(t *testing.T) {
		assert.HTTPError(t, router.ServeHTTP, "GET", "/admin/users/"+"defonotbase64", nil)
	})

	t.Run("ok", func(t *testing.T) {
		addUser(t, router, mockUserInfo)

		var got UserInfo
		err := json.Unmarshal([]byte(assert.HTTPBody(router.ServeHTTP, "GET", "/admin/users/"+mockUIDb64, nil)), &got)
		if err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, mockUserInfo, got)
	})
}

func TestDeleteUserHlr(t *testing.T) {
	router, cleaner := makeRouter(t)
	defer cleaner()

	t.Run("non-existent", func(t *testing.T) {
		assert.HTTPError(t, router.ServeHTTP, "DELETE", "/admin/users/"+base64.URLEncoding.EncodeToString([]byte("adsf")), nil)
	})

	t.Run("not base64", func(t *testing.T) {
		assert.HTTPError(t, router.ServeHTTP, "DELETE", "/admin/users/"+"defonotbase64", nil)
	})

	t.Run("ok", func(t *testing.T) {
		addUser(t, router, mockUserInfo)
		assert.HTTPSuccess(t, router.ServeHTTP, "DELETE", "/admin/users/"+mockUIDb64, nil)
		assert.HTTPError(t, router.ServeHTTP, "GET", "/admin/users/"+mockUIDb64, nil)
	})
}

func TestListAllUsersHlr(t *testing.T) {
	router, cleaner := makeRouter(t)
	defer cleaner()

	user1 := mockUserInfo
	addUser(t, router, user1)

	user2 := mockUserInfo
	user2.UID = []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
	addUser(t, router, user2)

	expected := []UserInfo{user1, user2}

	var got []UserInfo
	err := json.Unmarshal([]byte(assert.HTTPBody(router.ServeHTTP, "GET", "/admin/users", nil)), &got)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, assert.Subset(t, got, expected), assert.Subset(t, expected, got))
}
