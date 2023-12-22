<?php

$router->post(
    '/auth/generate',
    [
        'uses' => 'AuthGenerateController@process',
        'validator' => 'App\Domains\Auth\Http\Validators\AuthGenerateValidator'
    ]
);

if (config('app')['shouldUsePemToSignJWT']) {
    $router->get(
        '/auth/jwk/{context}',
        [
            'uses' => 'AuthPublicJwkController@process',
        ]
    );
}
