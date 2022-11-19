package types

type SignIn struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SignUp struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
