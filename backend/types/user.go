package types

type SignIn struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SignUp struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type OTP struct {
	Id  int64  `json:"id"`
	Otp string `json:"otp"`
}
