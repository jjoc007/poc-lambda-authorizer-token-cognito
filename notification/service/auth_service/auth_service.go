package auth_service

import (
	"context"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/dgrijalva/jwt-go"
	"github.com/jjoc007/poc-lambda-authorizer-token-cognito/notification/config/auth_config"
	"os"
	"strings"
)

// AuthService describes the structure a notification service.
type AuthService interface {
	Authorize(context.Context, events.APIGatewayWebsocketProxyRequest) (events.APIGatewayCustomAuthorizerResponse, error)
}

func New() AuthService {
	return &authService{
		region:            os.Getenv("AWS_REGION"),
		cognitoUserPoolID: os.Getenv("COGNITO_USER_POOL_ID"),
	}
}

type authService struct {
	region            string
	cognitoUserPoolID string
}

func (s *authService) Authorize(ctx context.Context, request events.APIGatewayWebsocketProxyRequest) (response events.APIGatewayCustomAuthorizerResponse, err error) {
	tokenJWT := request.QueryStringParameters["auth"]

	if tokenJWT == "" {
		tokenJWT = request.Headers["Authorization"]
		tokenJWT = strings.Split(tokenJWT, " ")[1] // when "Bearer token"
	}

	auth := auth_config.NewAuth(&auth_config.Config{
		CognitoRegion:     s.region,
		CognitoUserPoolID: s.cognitoUserPoolID,
	})

	token, err := auth.ParseJWT(tokenJWT)
	if err != nil {
		fmt.Sprint(err.Error())
		return
	}

	claims := token.Claims.(jwt.MapClaims)

	return events.APIGatewayCustomAuthorizerResponse{
		PrincipalID: "me",
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					[]string{"execute-api:*"},
					"Allow",
					[]string{"*"},
				},
			},
		},
		Context: claims,
	}, nil
}
