package handler

import (
	"encoding/json"
	"net/http"

	"github.com/GDSC-KMUTT/totp-session/service"
	"github.com/GDSC-KMUTT/totp-session/types"
	"github.com/GDSC-KMUTT/totp-session/utils"
)

type userHandler struct {
	service service.UserService
}

func NewUserHandler(service service.UserService) userHandler {
	return userHandler{service: service}
}

func (h userHandler) SignUp(w http.ResponseWriter, r *http.Request) {
	// Check if the request method is POST
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Set the response header to application/json
	w.Header().Set("Content-Type", "application/json")
	var body types.SignIn
	err := utils.Parse(r, &body)
	var response []byte
	if err != nil {
		response, _ = json.Marshal(map[string]any{"success": false, "error": err.Error()})
		w.WriteHeader(http.StatusBadRequest)
		w.Write(response)
		return
	}

	// Call signup service
	id, base64, secret, err := h.service.SignUp(body.Email, body.Password)
	if err != nil {
		response, _ = json.Marshal(map[string]any{"success": false, "error": err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(response)
		return
	}

	// Create a response
	response, _ = json.Marshal(map[string]any{"success": true, "id": id, "image": base64, "secret": secret})
	w.Write(response)
	return
}

func (h userHandler) SignIn(w http.ResponseWriter, r *http.Request) {
	h.service.SignIn("", "")
	w.Write([]byte("User signed in!"))
}
