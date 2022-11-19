package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"net/http"
	"strings"
	"time"

	"github.com/GDSC-KMUTT/totp-session/config"
	"github.com/GDSC-KMUTT/totp-session/handler"
	"github.com/GDSC-KMUTT/totp-session/repository"
	"github.com/GDSC-KMUTT/totp-session/service"
	"github.com/GDSC-KMUTT/totp-session/types"
	"github.com/GDSC-KMUTT/totp-session/utils"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	my_port := ":8080"
	s := &http.Server{
		Addr:           my_port,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	db, err := sql.Open("mysql", config.C.DB_HOST)
	if err != nil {
		panic(err)
	}
	fmt.Println("port start", my_port)

	userRepo := repository.NewUserRepositoryDB(db)
	userService := service.NewUserService(userRepo)
	userHandler := handler.NewUserHandler(userService)

	http.HandleFunc("/signup", CORS(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.Body)

		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		var response []byte
		var body types.SignUp
		err := utils.Parse(r, &body)
		if err != nil {
			response, _ = json.Marshal(map[string]any{"success": false, "error": "Error"})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(response)
		}
		// secret := key.Secret
		// Generate a new secret TOTP key
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "GDSC KMUTT",
			AccountName: body.Email,
		})
		if err != nil {
			response, _ = json.Marshal(map[string]any{"success": false, "error": err.Error()})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(response)
			return
		}
		secret := key.Secret()

		hashedPwd, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
		if err != nil {
			response, _ = json.Marshal(map[string]any{"success": false, "error": err.Error()})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(response)
			return
		}

		insert, err := db.Exec("INSERT INTO users (email, password, secret) VALUES (?, ?, ?)", body.Email, hashedPwd, secret)
		if err != nil {
			response, _ = json.Marshal(map[string]any{"success": false, "error": err.Error()})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(response)
			return
		}

		userId, err := insert.LastInsertId()
		if err != nil {
			response, _ = json.Marshal(map[string]any{"success": false, "error": err.Error()})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(response)
			return
		}

		var buf bytes.Buffer
		img, err := key.Image(200, 200)
		if err != nil {
			response, _ = json.Marshal(map[string]any{"success": false, "error": err.Error()})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(response)
			return
		}
		if err := png.Encode(&buf, img); err != nil {
			response, _ = json.Marshal(map[string]any{"success": false, "error": err.Error()})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(response)
			return
		}
		base64string := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
		if err != nil {
			response, _ = json.Marshal(map[string]any{"success": false, "error": err.Error()})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(response)
			return
		}
		url := key.URL()

		// Create a response
		response, _ = json.Marshal(map[string]any{"success": true, "id": userId, "image": base64string, "secret": url})
		w.Write(response)

	}))

	http.HandleFunc("/signin2", userHandler.SignIn)

	http.HandleFunc("/signin", CORS(func(w http.ResponseWriter, r *http.Request) {
		// POST request
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		var response []byte
		var body types.SignIn

		err := utils.Parse(r, &body)
		if err != nil {
			response, _ = json.Marshal(map[string]any{"success": false, "error": "Error"})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(response)
		}
		if err != nil {
			response, _ = json.Marshal(map[string]any{"success": false, "error": err.Error()})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(response)
			return
		}

		// hashedPwd, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
		// if err != nil {
		// 	response, _ = json.Marshal(map[string]any{"success": false, "error": err.Error()})
		// 	w.WriteHeader(http.StatusInternalServerError)
		// 	w.Write(response)
		// 	return
		// }
		var user repository.User

		// var id int64
		// var email string
		// var password string
		// var secret string

		err = db.QueryRow("SELECT id, email, password, secret FROM users WHERE email = ?", body.Email).Scan(&user.Id, &user.Email, &user.Password, &user.Secret)
		if err != nil {
			response, _ = json.Marshal(map[string]any{"success": false, "error": err.Error()})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(response)
			return
		}
		fmt.Println(user.Email)

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

		if err != nil {
			response, _ = json.Marshal(map[string]any{"success": false, "error": err.Error()})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(response)
			return
		}

		response, _ = json.Marshal(map[string]any{"success": true, "id": user.Id})

		w.Write(response)

		// w.Write()

		// Body {email, password}
		// Response {success, id}
	}))

	http.HandleFunc("/confirm-otp", CORS(func(w http.ResponseWriter, r *http.Request) {

		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		var response []byte
		var body types.OTP

		err := utils.Parse(r, &body)
		if err != nil {
			response, _ = json.Marshal(map[string]any{"success": false, "error": err.Error()})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(response)
			return
		}
		var user repository.User

		// var id int64
		// var email string
		// var password string
		// var secret string

		err = db.QueryRow("SELECT id, email, password, secret FROM users WHERE id = ?", body.Id).Scan(&user.Id, &user.Email, &user.Password, &user.Secret)
		if err != nil {
			response, _ = json.Marshal(map[string]any{"success": false, "error": err.Error()})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(response)
			return
		}

		// POST request
		// Body {id, otp}
		// Response {success, token}
		if !totp.Validate(body.Otp, user.Secret) {
			response, _ = json.Marshal(map[string]any{"success": false, "error": "OTP invalid"})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(response)
			return
		}

		claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"id": user.Id,
		})
		token, err := claims.SignedString([]byte(config.C.JWT_SECRET))
		if err != nil {
			response, _ = json.Marshal(map[string]any{"success": false, "error": "OTP invalid"})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(response)
			return
		}

		response, _ = json.Marshal(map[string]any{"success": true, "token": token})

		w.Write(response)

	}))
	type CustomClaims struct {
		Id int64 `json:"id"`
		jwt.StandardClaims
	}
	http.HandleFunc("/get-user", CORS(func(w http.ResponseWriter, r *http.Request) {
		// GET request
		// Header authorization "Bearer {token}"
		// Response {success, email}
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		reqToken := r.Header.Get("Authorization")
		splitToken := strings.Split(reqToken, "Bearer ")
		reqToken = splitToken[1]
		var response []byte

		token, err := jwt.ParseWithClaims(reqToken, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(config.C.JWT_SECRET), nil
		})
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		claims, ok := token.Claims.(*CustomClaims)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var user repository.User

		err = db.QueryRow("SELECT id, email, password, secret FROM users WHERE id = ?", claims.Id).Scan(&user.Id, &user.Email, &user.Password, &user.Secret)
		if err != nil {
			response, _ = json.Marshal(map[string]any{"success": false, "error": err.Error()})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(response)
			return
		}

		response, _ = json.Marshal(map[string]any{"success": true, "email": user.Email})
		w.Write(response)

	}))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		w.Write([]byte("Hello World"))
	})

	if err := s.ListenAndServe(); err != nil {
		panic(err)
	}

	defer db.Close()
}
func CORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Access-Control-Allow-Origin", "http://127.0.0.1:3000")
		w.Header().Add("Access-Control-Allow-Credentials", "true")
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		w.Header().Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")

		if r.Method == "OPTIONS" {
			http.Error(w, "No Content", http.StatusNoContent)
			return
		}

		next(w, r)
	}
}
