<?php

$router->post(
    '/auth/generate',
    [
        'uses' => 'AuthGenerateController@process',
        'validator' => 'App\Domains\Auth\Http\Validators\AuthGenerateValidator'
    ]
);

$router->get(
    '/auth/jwk/{context}',
    [
        'uses' => 'AuthPublicJwkController@process',
    ]
);
