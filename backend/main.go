package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"net/http"
	"time"

	"github.com/GDSC-KMUTT/totp-session/config"
	"github.com/GDSC-KMUTT/totp-session/handler"
	"github.com/GDSC-KMUTT/totp-session/repository"
	"github.com/GDSC-KMUTT/totp-session/service"
	"github.com/GDSC-KMUTT/totp-session/types"
	"github.com/GDSC-KMUTT/totp-session/utils"
	_ "github.com/go-sql-driver/mysql"
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

	// http.HandleFunc("/signup", userHandler.SignUp)
	http.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
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

	})

	// func(w http.ResponseWriter, r *http.Request) {

	// 	// POST request
	// 	fmt.Printf("%s", r.Method)
	// 	// res, err := http.Get("/signup")
	// 	// if err != nil {
	// 	// 	fmt.Printf("error making http request: %s\n", err)
	// 	// }
	// 	fmt.Fprintf(w, `{"message": "hello!"}`)

	// 	// Body {email, password}
	// 	// Response {success, id, URL, base64}
	// })

	http.HandleFunc("/signin", userHandler.SignIn)

	// http.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
	// 	// POST request
	// 	// Body {email, password}
	// 	// Response {success, id}
	// })

	http.HandleFunc("/confirm-otp", func(w http.ResponseWriter, r *http.Request) {
		// POST request
		// Body {id, otp}
		// Response {success, token}
	})

	http.HandleFunc("/get-user", func(w http.ResponseWriter, r *http.Request) {
		// GET request
		// Header authorization "Bearer {token}"
		// Response {success, email}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		w.Write([]byte("Hello World"))
	})

	if err := s.ListenAndServe(); err != nil {
		panic(err)
	}

	defer db.Close()
}
