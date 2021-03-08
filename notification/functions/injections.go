package functions

import (
	"github.com/jjoc007/poc-lambda-authorizer-token-cognito/notification/log"
	serviceauth "github.com/jjoc007/poc-lambda-authorizer-token-cognito/notification/service/auth_service"
)

// Instances is a global map that contain all object instances of app
var Instances = MakeDependencyInjection()

// MakeDependencyInjection Initialize all dependencies
func MakeDependencyInjection() map[string]interface{} {
	log.Logger.Debug().Msg("Start bootstrap app objects")
	instances := make(map[string]interface{})

	instances["authService"] = serviceauth.New()

	log.Logger.Debug().Msg("End bootstrap app objects")
	return instances
}
