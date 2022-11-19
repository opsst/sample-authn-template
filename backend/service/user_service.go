package service

import (
	"bytes"
	"encoding/base64"
	"image/png"

	"github.com/GDSC-KMUTT/totp-session/repository"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

type userService struct {
	repository repository.UserRepository
}

func NewUserService(userRepository repository.UserRepository) userService { // รับ "Adapter" ของ Repository
	return userService{repository: userRepository}
}

func (s userService) SignUp(email string, password string) (*int64, *string, *string, error) {
	// Generate a new secret TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "GDSC KMUTT",
		AccountName: email,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	secret := key.Secret()

	// Hash the password
	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create a new user
	user, err := s.repository.CreateUser(email, string(hashedPwd), secret)
	if err != nil {
		return nil, nil, nil, err
	}

	// Convert TOTP key into a PNG
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := png.Encode(&buf, img); err != nil {
		return nil, nil, nil, err
	}
	base64string := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
	url := key.URL()
	return &user.Id, &base64string, &url, nil
}

func (s userService) SignIn(email string, password string) (*int64, *string, *string, error) {
	s.repository.CheckUser(email)
	return nil, nil, nil, nil
}
