package webauthn

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/Untanky/iam-auth/oauth2"
	"github.com/Untanky/iam-auth/utils"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
)

type AuthenticationController struct {
	userRepo   UserRepository
	authZState utils.Cache[string, *LoginResponse]
	authNState utils.ReadCache[string, *oauth2.AuthorizationRequest]
	webauthn   *WebAuthn
}

func (controller *AuthenticationController) Init(userRepo UserRepository, authZState utils.Cache[string, *LoginResponse], authNState utils.ReadCache[string, *oauth2.AuthorizationRequest], webauthn *WebAuthn) {
	controller.userRepo = userRepo
	controller.webauthn = webauthn
	controller.authNState = authNState
	controller.authZState = authZState
}

func (controller *AuthenticationController) Authenticate(c *gin.Context) {
	body := AuthenticateRequest{}
	if err := c.ShouldBind(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "could not parse body",
		})
		fmt.Println(err)
		return
	}

	user, _ := controller.userRepo.FindByIdentifier(body.Identifier)

	var response interface{}
	if user != nil {
		response = controller.webauthn.BeginLogin(user)
		c.Header("Next-Step", "login")
	} else {
		response = controller.webauthn.BeginRegister(&User{
			Credentials: []Credential{},
			Identifier:  body.Identifier,
		})
		c.Header("Next-Step", "register")
	}
	c.JSON(http.StatusOK, response)
}

func (controller *AuthenticationController) Register(c *gin.Context) {
	body := RegisterRequest{}
	err := json.NewDecoder(c.Request.Body).Decode(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "could not parse body",
		})
		fmt.Println("Error", err)
		return
	}

	user, err := controller.webauthn.FinishRegister(body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "could not validate registration",
		})
		fmt.Println(err)
		return
	}

	err = controller.userRepo.Create(user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "could not store user data",
		})
		fmt.Println(err)
		return
	}

	c.JSON(http.StatusOK, nil)
}

func (controller *AuthenticationController) Login(c *gin.Context) {
	body := LoginRequest{}
	if err := c.ShouldBind(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "could not parse body",
		})
		fmt.Println(err)
		return
	}

	// Implementation of https://w3c.github.io/webauthn/#sctn-verifying-assertion
	challengeId, _ := base64.RawStdEncoding.DecodeString(body.Response.ClientData.Challenge)
	challange, err := controller.authZState.Get(string(challengeId))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": errors.New("no valid challenge found"),
		})
		return
	}

	// Implementation of https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
	user, err := controller.userRepo.FindByIdentifier(body.Response.UserHandle)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	err = controller.webauthn.FinishLogin(&body, challange, user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, nil)
}

func (controller *AuthenticationController) Routes(rg *gin.RouterGroup) {
	rg.POST("", controller.Authenticate)
	rg.POST("/register", controller.Register)
	rg.POST("/login", controller.Login)
}
