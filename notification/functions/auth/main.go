package main

import (
	"context"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/jjoc007/poc-lambda-authorizer-token-cognito/notification/functions"

	serviceauth "github.com/jjoc007/poc-lambda-authorizer-token-cognito/notification/service/auth_service"
)

func LambdaHandler(cxt context.Context, event events.APIGatewayWebsocketProxyRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	return functions.Instances["authService"].(serviceauth.AuthService).Authorize(cxt, event)
}

func main() {
	lambda.Start(LambdaHandler)
}
