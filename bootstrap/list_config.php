<?php

require __DIR__.'/list_routes.php';

$authMiddleware = 'auth';
if (config('app.usePemToSignJWT')) {
    $authMiddleware = 'authJwk';
}

$listConfigs = [
    [
        'middleware' => [],
        'routes' => [
            'App\Domains\Health\Http\Controllers' => 'health',
        ],
    ],
    [
        'middleware' => [
            'start',
            'validator',
        ],
        'routes' => [
            'App\Domains\Auth\Http\Controllers' => 'auth',
        ],
    ],
    [
        'middleware' => [
            $authMiddleware,
            'start',
            'suffix',
            'validator',
            'filters',
            'parameter',
        ],
        'routes' => $listRoutes,
    ],
];
