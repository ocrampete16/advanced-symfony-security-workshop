<?php

require_once 'vendor/autoload.php';

use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager;
use Symfony\Component\Security\Core\Authorization\Voter\RoleVoter;

const PROVIDER_KEY = 'default';

// WRITE CODE AFTER THIS

/**
 * Verwenden solltet ihr:
 * - InMemoryUserProvider
 * - PlaintextPasswordEncoder
 * - DaoAuthenticationProvider
 */

// WRITE CODE BEFORE THIS

// Tokens
$adminToken = new UsernamePasswordToken('admin', 'admin-password', PROVIDER_KEY);
$userToken = new UsernamePasswordToken('user', 'user-password', PROVIDER_KEY);
$neverAuthenticateToken = new UsernamePasswordToken('never', 'never-password', PROVIDER_KEY);

// Authentication
$adminToken = $authenticationManager->authenticate($adminToken);
$userToken = $authenticationManager->authenticate($userToken);
$neverAuthenticateToken = $authenticationManager->authenticate($neverAuthenticateToken);
if (!$adminToken->isAuthenticated() || !$userToken->isAuthenticated()) {
    throw new RuntimeException('User is not authenticated!');
}
if ($neverAuthenticateToken->isAuthenticated()) {
    throw new RuntimeException('$neverAuthenticateToken must not be authenticated!');
}
echo 'Authentication succeeded!'.PHP_EOL;

// Authorization
$accessDecisionManager = new AccessDecisionManager([new RoleVoter()]);

$adminIsAdmin = $accessDecisionManager->decide($adminToken, ['ROLE_ADMIN']);
$adminIsUser = $accessDecisionManager->decide($adminToken, ['ROLE_USER']);
$userIsAdmin = $accessDecisionManager->decide($userToken, ['ROLE_ADMIN']);
$userIsUser = $accessDecisionManager->decide($userToken, ['ROLE_USER']);

if (!$adminIsAdmin || $adminIsUser || $userIsAdmin || !$userIsUser) {
    throw new RuntimeException('Somethings not right yet!');
}
echo 'Well, it is now!'.PHP_EOL;
