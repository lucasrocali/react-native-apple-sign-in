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
    if (@available(iOS 13.0, *)) {
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
    } else {
       return @{};
    }
}


+ (BOOL)requiresMainQueueSetup
{
  return YES;
}


RCT_EXPORT_METHOD(requestAsync:(NSDictionary *)options
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    if (@available(iOS 13.0, *)) {
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
    } else {
        NSError *error = nil;
        reject(@"error", @"Not Supported",error);
    }
}


- (ASPresentationAnchor)presentationAnchorForAuthorizationController:(ASAuthorizationController *)controller  API_AVAILABLE(ios(13.0)){
  return RCTKeyWindow();
}


- (void)authorizationController:(ASAuthorizationController *)controller
   didCompleteWithAuthorization:(ASAuthorization *)authorization  API_AVAILABLE(ios(13.0)){
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
    if (_promiseResolve) {
        _promiseResolve(user);
        _promiseResolve = nil;
    }
}


-(void)authorizationController:(ASAuthorizationController *)controller
          didCompleteWithError:(NSError *)error  API_AVAILABLE(ios(13.0)){
    NSLog(@" Error code%@", error);
 
    if (_promiseReject) {
           _promiseReject(@"authorization", error.description, error);
           _promiseReject = nil;
    }
}


@end