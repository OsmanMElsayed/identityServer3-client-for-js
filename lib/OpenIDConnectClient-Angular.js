//----------------------------------------------------------------------
// OpenIDConnect v1.0.0 - forked from AdalJS v 1.0.5
// @preserve Copyright (c) Microsoft Open Technologies, Inc.
// @preserve Copyright (c) Osman M Elsayed.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//----------------------------------------------------------------------
'use strict';

if (typeof module !== 'undefined' && module.exports) {
    module.exports.inject = function (conf) {
        return new AuthenticationContext(conf);
    };
}

(function () {
    // ============= Angular modules- Start =============
    if (angular) {
        
        var OpenIDConnectClientModule = angular.module('OpenIDConnectClient', []);
        
        OpenIDConnectClientModule.provider('openIDConnectAuthenticationService', function () {
            
            var _self = this;
            var _authenticationContext = null;
            var _oauthData = { isAuthenticated: false, userName: '', loginError: '', profile: '' };
            
            var updateDataFromCache = function () {
                // only cache lookup here to not interrupt with events
                var id_token = _authenticationContext.getCachedToken(_authenticationContext.CONSTANTS.ID_TOKEN);
                
                _oauthData.isAuthenticated = id_token !== null && id_token.length > 0;
                var user = _authenticationContext.getCachedUser() || { userName: '' };
                
                _oauthData.userName = user.userName;
                _oauthData.profile = user.profile;
                _oauthData.loginError = _authenticationContext.getLoginError();
            };
            
            this.init = function (configOptions, httpProvider) {
                if (configOptions) {
                    // redirect and logout_redirect are set to current location by default
                    var existingHash = window.location.hash;
                    var pathDefault = window.location.href;
                    if (existingHash) {
                        pathDefault = pathDefault.replace(existingHash, '');
                    }
                    configOptions.redirectUri = configOptions.redirectUri || pathDefault;
                    configOptions.postLogoutRedirectUri = configOptions.postLogoutRedirectUri || pathDefault;
                    
                    if (httpProvider && httpProvider.interceptors) {
                        httpProvider.interceptors.push('ProtectedResourceInterceptor');
                    }
                    
                    // create instance with given config
                    _authenticationContext = new AuthenticationContext(configOptions);
                } else {
                    throw new Error('You must set configOptions, when calling init');
                }
                
                // Set authenticated status
                updateDataFromCache();
            };
            
            // special function that exposes methods in Angular controller
            // $rootScope, $window, $q, $location, $timeout are injected by Angular
            this.$get = ['$rootScope', '$window', '$q', '$location', '$timeout', function ($rootScope, $window, $q, $location, $timeout) {
                    
                    var locationChangeHandler = function () {
                        var hash = $window.location.hash;
                        
                        alert('Hi from location change handler ! Hash is : ' + hash);
                        
                        if (_authenticationContext.isCallback(hash)) {
                            // callback can come from login or iframe request
                            
                            var requestInfo = _authenticationContext.getRequestInfo(hash);
                            _authenticationContext.saveTokenFromHash(requestInfo);
                            
                            if ($location.$$html5) {
                                $window.location = $window.location.origin + $window.location.pathname;
                            } else {
                                $window.location.hash = '';
                            }
                            
                            if (requestInfo.requestType !== _authenticationContext.REQUEST_TYPE.LOGIN) {
                                _authenticationContext.callback = $window.parent.AuthenticationContext().callback;
                                if (requestInfo.requestType === _authenticationContext.REQUEST_TYPE.RENEW_TOKEN) {
                                    _authenticationContext.callback = $window.parent.callBackMappedToRenewStates[requestInfo.stateResponse];
                                }
                            }
                            
                            // Return to callback if it is send from iframe
                            if (requestInfo.stateMatch) {
                                if (typeof _authenticationContext.callback === 'function') {
                                    // Call within the same context without full page redirect keeps the callback
                                    if (requestInfo.requestType === _authenticationContext.REQUEST_TYPE.RENEW_TOKEN) {
                                        // Idtoken or Accestoken can be renewed
                                        if (requestInfo.parameters['access_token']) {
                                            _authenticationContext.callback(_authenticationContext._getItem(_authenticationContext.CONSTANTS.STORAGE.ERROR_DESCRIPTION), requestInfo.parameters['access_token']);
                                            return;
                                        } else if (requestInfo.parameters['id_token']) {
                                            _authenticationContext.callback(_authenticationContext._getItem(_authenticationContext.CONSTANTS.STORAGE.ERROR_DESCRIPTION), requestInfo.parameters['id_token']);
                                            return;
                                        }
                                    }
                                } else {
                                    // normal full login redirect happened on the page
                                    updateDataFromCache();
                                    if (_oauthData.isAuthenticated) {
                                        //IDtoken is added as token for the app
                                        $timeout(function () {
                                            updateDataFromCache();
                                            $rootScope.userInfo = _oauthData;
                                            // redirect to login requested page
                                            var loginStartPage = _authenticationContext._getItem(_authenticationContext.CONSTANTS.STORAGE.START_PAGE);
                                            if (loginStartPage) {
                                                $location.path(loginStartPage);
                                            }
                                        }, 1);
                                        $rootScope.$broadcast('openIDConnectClient:loginSuccess');
                                    } else {
                                        $rootScope.$broadcast('openIDConnectClient:loginFailure', _authenticationContext._getItem(_authenticationContext.CONSTANTS.STORAGE.ERROR_DESCRIPTION));
                                    }
                                }
                            }
                        } else {
                            // No callback. App resumes after closing or moving to new page.
                            // Check token and username             
                            updateDataFromCache();
                            if (!_authenticationContext._renewActive && !_oauthData.isAuthenticated && _oauthData.userName) {
                                if (!_authenticationContext._getItem(_authenticationContext.CONSTANTS.STORAGE.FAILED_RENEW)) {
                                    // Idtoken is expired or not present
                                    _authenticationContext.acquireToken(_authenticationContext.CONSTANTS.ID_TOKEN , function (error, tokenOut) {
                                        if (error) {
                                            $rootScope.$broadcast('openIDConnectClient:loginFailure', 'auto renew failure');
                                        } else {
                                            if (tokenOut) {
                                                _oauthData.isAuthenticated = true;
                                            }
                                        }
                                    });
                                }
                            }
                        }
                        
                        $timeout(function () {
                            updateDataFromCache();
                            $rootScope.userInfo = _oauthData;
                        }, 1);
                    };
                    
                    var loginHandler = function () {
                        _authenticationContext._logstatus('Login event for:' + $location.$$path);
                        if (_authenticationContext.config && _authenticationContext.config.localLoginUrl) {
                            $location.path(_authenticationContext.config.localLoginUrl);
                        } else {
                            // directly start login flow
                            _authenticationContext._saveItem(_authenticationContext.CONSTANTS.STORAGE.START_PAGE, $location.$$path);
                            _authenticationContext._logstatus('Start login at:' + window.location.href);
                            $rootScope.$broadcast('openIDConnectClient:loginRedirect');
                            _authenticationContext.login();
                        }
                    };
                    
                    function isAccessTokenRequired(route, global) {
                        return global.requireAccessToken ? route.requireAccessToken !== false : !!route.requireAccessToken;
                    }
                    
                    var routeChangeHandler = function (e, nextRoute) {
                        _authenticationContext._logstatus('Route change event for:' + $location.$$path);
                        
                        if (nextRoute && nextRoute.$$route && isAccessTokenRequired(nextRoute.$$route, _authenticationContext.config)) {
                            if (!_oauthData.isAuthenticated) {
                                loginHandler();
                            }
                        }
                    };
                    
                    var stateChangeHandler = function (e, nextRoute) {
                        _authenticationContext._logstatus('State change event for:' + $location.$$path);
                        
                        if (nextRoute && isAccessTokenRequired(nextRoute, _authenticationContext.config)) {
                            if (!_oauthData.isAuthenticated) {
                                loginHandler();
                            }
                        }
                    };
                    
                    // Route change event tracking to receive fragment and also auto renew tokens
                    $rootScope.$on('$routeChangeStart', routeChangeHandler);
                    
                    $rootScope.$on('$stateChangeStart', stateChangeHandler);
                    
                    $rootScope.$on('$locationChangeStart', locationChangeHandler);
                    
                    updateDataFromCache();
                    $rootScope.userInfo = _oauthData;
                    
                    return {
                        // public methods will be here that are accessible from Controller
                        loginCallback: function (callback) {
                            _authenticationContext.config.displayCall = callback;
                        },
                        isAccessTokenRequired: function (isAccessTokenRequired) {
                            _authenticationContext.config.isAccessTokenRequired = isAccessTokenRequired;
                        },
                        config: _authenticationContext.config,
                        login: function () {
                            _authenticationContext.login();
                        },
                        loginInProgress: function () {
                            return _authenticationContext.loginInProgress();
                        },
                        logOut: function () {
                            _authenticationContext.logOut();
                        //call signout related method
                        },
                        getCachedAccessToken: function () {
                            return _authenticationContext.getCachedToken(_authenticationContext.CONSTANTS.ACCESS_TOKEN);
                        },
                        getCachedIdToken: function () {
                            return _authenticationContext.getCachedToken(_authenticationContext.CONSTANTS.ID_TOKEN);
                        },
                        userInfo: _oauthData,
                        acquireAccessToken: function () {
                            // automated token request call
                            var deferred = $q.defer();
                            _authenticationContext.acquireToken(_authenticationContext.CONSTANTS.ACCESS_TOKEN, function (error, tokenOut) {
                                if (error) {
                                    _authenticationContext._logstatus('err :' + error);
                                    deferred.reject(error);
                                } else {
                                    deferred.resolve(tokenOut);
                                }
                            });
                            
                            return deferred.promise;
                        },
                        getUser: function () {
                            var deferred = $q.defer();
                            _authenticationContext.getUser(function (error, user) {
                                if (error) {
                                    _authenticationContext._logstatus('err :' + error);
                                    deferred.reject(error);
                                } else {
                                    deferred.resolve(user);
                                }
                            });
                            
                            return deferred.promise;
                        },
                        clearCache: function () {
                            _authenticationContext.clearCache();
                        }
                    };
                }];
        });
        
        // Interceptor for http if needed
        OpenIDConnectClientModule.factory('ProtectedResourceInterceptor', ['openIDConnectAuthenticationService', '$q', '$rootScope', function (authService, $q, $rootScope) {
                
                return {
                    request: function (config) {
                        if (config) {
                            
                            // This interceptor needs to load service, but dependeny definition causes circular reference error.
                            // Loading with injector is suggested at github. https://github.com/angular/angular.js/issues/2367
                            
                            config.headers = config.headers || {};
                            
                            var tokenStored = authService.getCachedAccessToken();
                            
                            if (tokenStored) {
                                // check endpoint mapping if provided
                                config.headers.Authorization = 'Bearer ' + tokenStored;
                                return config;
                            } else {
                                // Cancel request if login is starting
                                if (authService.loginInProgress()) {
                                    return $q.reject();
                                } else if (authService.config) {
                                    // external endpoints
                                    // delayed request to return after iframe completes
                                    var delayedRequest = $q.defer();
                                    authService.acquireAccessToken().then(function (token) {
                                        config.headers.Authorization = 'Bearer ' + token;
                                        delayedRequest.resolve(config);
                                    }, function (err) {
                                        delayedRequest.reject(err);
                                    });
                                    
                                    return delayedRequest.promise;
                                }
                            }
                            
                            return config;
                        }
                    },
                    responseError: function (rejection) {
                        if (rejection && rejection.status === 401) {
                            $rootScope.$broadcast('openIDConnectClient:notAuthorized', rejection);
                        }
                        
                        return $q.reject(rejection);
                    }
                };
            }]);
    } else {
        console.error('Angular.JS is not included');
    }
}());
