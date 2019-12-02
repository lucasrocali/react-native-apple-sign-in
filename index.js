import React, { Component } from 'react';
import { NativeModules, requireNativeComponent, Platform } from 'react-native';

const { AppleSignIn } = NativeModules;

export const RNSignInWithAppleButton = requireNativeComponent('RNCSignInWithAppleButton');

export const SignInWithAppleButton = (buttonStyle, callBack) => {
  if (Platform.OS === 'ios') {
    return <RNSignInWithAppleButton style={buttonStyle} onPress={async () => {

      await RNCAppleAuthentication.requestAsync({
        scopes: [RNCAppleAuthentication.Scope.FULL_NAME, RNCAppleAuthentication.Scope.EMAIL],
      }).then((response) => {
        callBack(response) //Display response
      }, (error) => {
        callBack(error) //Display error

      });

    }} />
  } else {
    return null

  }

}

export const AppleSignInAction = async () => {
  return AppleSignIn.requestAsync({})

}

export default AppleSignIn;
