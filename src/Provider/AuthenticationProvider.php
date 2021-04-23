<?php

namespace App\Provider;

use Authentication\AuthenticationService;
use Authentication\AuthenticationServiceInterface;
use Authentication\AuthenticationServiceProviderInterface;
use Authentication\Identifier\IdentifierInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthenticationProvider implements AuthenticationServiceProviderInterface
{
    /**
     * Returns a service provider instance.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request Request
     * @return \Authentication\AuthenticationServiceInterface
     */
    public function getAuthenticationService(ServerRequestInterface $request): AuthenticationServiceInterface
    {
        $service = new AuthenticationService();

        $fields = [
            IdentifierInterface::CREDENTIAL_USERNAME => 'email',
            IdentifierInterface::CREDENTIAL_PASSWORD => 'password',
        ];

        // Put form authentication first so that users can re-login via
        // the login form if necessary.
        $service->loadAuthenticator('Authentication.Form', [
            'loginUrl' => '/auth/login',
            'fields' => [
                IdentifierInterface::CREDENTIAL_USERNAME => 'email',
                IdentifierInterface::CREDENTIAL_PASSWORD => 'password',
            ],
        ]);
        // Then use sessions if they are active.
        $service->loadAuthenticator('Authentication.Session');

        // If the user is on the login page, check for a cookie as well.
        $service->loadAuthenticator('Authentication.Cookie', [
            'fields' => $fields,
            'loginUrl' => '/auth/login',
        ]);

        return $service;
    }
}
