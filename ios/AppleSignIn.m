#import "AppleSignIn.h"

#import <React/RCTUtils.h>
@implementation AppleSignIn

-(dispatch_queue_t)methodQueue
{
    return dispatch_get_main_queue();
}

RCT_EXPORT_MODULE()

-(NSDictionary *)constantsToExport
{
  NSDictionary* scopes = @{@"FULL_NAME": ASAuthorizationScopeFullName, @"EMAIL": ASAuthorizationScopeEmail};
  NSDictionary* operations = @{
    @"LOGIN": ASAuthorizationOperationLogin,
    @"REFRESH": ASAuthorizationOperationRefresh,
    @"LOGOUT": ASAuthorizationOperationLogout,
    @"IMPLICIT": ASAuthorizationOperationImplicit
  };
  NSDictionary* credentialStates = @{
    @"AUTHORIZED": @(ASAuthorizationAppleIDProviderCredentialAuthorized),
    @"REVOKED": @(ASAuthorizationAppleIDProviderCredentialRevoked),
    @"NOT_FOUND": @(ASAuthorizationAppleIDProviderCredentialNotFound),
  };
  NSDictionary* userDetectionStatuses = @{
    @"LIKELY_REAL": @(ASUserDetectionStatusLikelyReal),
    @"UNKNOWN": @(ASUserDetectionStatusUnknown),
    @"UNSUPPORTED": @(ASUserDetectionStatusUnsupported),
  };
  
  return @{
           @"Scope": scopes,
           @"Operation": operations,
           @"CredentialState": credentialStates,
           @"UserDetectionStatus": userDetectionStatuses
           };
}


+ (BOOL)requiresMainQueueSetup
{
  return YES;
}


RCT_EXPORT_METHOD(requestAsync:(NSDictionary *)options
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
  _promiseResolve = resolve;
  _promiseReject = reject;
  
  ASAuthorizationAppleIDProvider* appleIDProvider = [[ASAuthorizationAppleIDProvider alloc] init];
  ASAuthorizationAppleIDRequest* request = [appleIDProvider createRequest];
  request.requestedScopes = options[@"scopes"];
  if (options[@"operations"]) {
    request.requestedOperation = options[@"operations"];
  }
  
  ASAuthorizationController* ctrl = [[ASAuthorizationController alloc] initWithAuthorizationRequests:@[request]];
  ctrl.presentationContextProvider = self;
  ctrl.delegate = self;
  [ctrl performRequests];
}


- (ASPresentationAnchor)presentationAnchorForAuthorizationController:(ASAuthorizationController *)controller {
  return RCTKeyWindow();
}


- (void)authorizationController:(ASAuthorizationController *)controller
   didCompleteWithAuthorization:(ASAuthorization *)authorization {
  ASAuthorizationAppleIDCredential* credential = authorization.credential;
  NSDictionary* user = @{
                         @"givenName": RCTNullIfNil(credential.fullName.givenName),
                         @"familyName": RCTNullIfNil(credential.fullName.familyName),
                         @"email": RCTNullIfNil(credential.email),
                         @"user": credential.user,
                         @"authorizedScopes": credential.authorizedScopes,
                         @"realUserStatus": @(credential.realUserStatus),
                         @"state": RCTNullIfNil(credential.state),
                         @"authorizationCode": [[NSString alloc] initWithData:credential.authorizationCode encoding:NSASCIIStringEncoding],
                         @"identityToken": [[NSString alloc] initWithData:credential.identityToken encoding:NSASCIIStringEncoding],
                         };
  _promiseResolve(user);
}


-(void)authorizationController:(ASAuthorizationController *)controller
           didCompleteWithError:(NSError *)error {
    NSLog(@" Error code%@", error);
  _promiseReject(@"authorization", error.description, error);
}
//RCT_EXPORT_METHOD(sampleMethod:(NSString *)stringArgument numberParameter:(nonnull NSNumber *)numberArgument callback:(RCTResponseSenderBlock)callback)
//{
//    // TODO: Implement some actually useful functionality
//    callback(@[[NSString stringWithFormat: @"numberArgument: %@ stringArgument: %@", numberArgument, stringArgument]]);
//}


@end
