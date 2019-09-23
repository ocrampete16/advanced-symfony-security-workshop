<?php

declare(strict_types=1);

namespace App\Security;

use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolverInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

final class MultiFactorAuthenticationTrustResolver implements MultiFactorAuthenticationTrustResolverInterface
{
    private $authenticationTrustResolver;

    public function __construct(AuthenticationTrustResolverInterface $authenticationTrustResolver)
    {
        $this->authenticationTrustResolver = $authenticationTrustResolver;
    }

    public function isAnonymous(TokenInterface $token = null)
    {
        return $this->authenticationTrustResolver->isAnonymous($token);
    }

    public function isRememberMe(TokenInterface $token = null)
    {
        return $this->authenticationTrustResolver->isRememberMe($token);
    }

    public function isFullFledged(TokenInterface $token = null)
    {
        return $this->authenticationTrustResolver->isFullFledged($token) && !$this->isPartiallyAuthenticated($token);
    }

    public function isPartiallyAuthenticated(TokenInterface $token = null): bool
    {
        return $token instanceof MidAuthenticationGuardToken;
    }
}
