<?php

declare(strict_types=1);

namespace App\Security;

use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolverInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

interface MultiFactorAuthenticationTrustResolverInterface extends AuthenticationTrustResolverInterface
{
    public function isPartiallyAuthenticated(TokenInterface $token = null): bool;
}
