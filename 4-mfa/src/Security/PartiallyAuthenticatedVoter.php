<?php

declare(strict_types=1);

namespace App\Security;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

final class PartiallyAuthenticatedVoter extends Voter
{
    private $multiFactorAuthenticationTrustResolver;

    public function __construct(MultiFactorAuthenticationTrustResolverInterface $multiFactorAuthenticationTrustResolver)
    {
        $this->multiFactorAuthenticationTrustResolver = $multiFactorAuthenticationTrustResolver;
    }

    protected function supports($attribute, $subject)
    {
        return 'IS_PARTIALLY_AUTHENTICATED' === $attribute;
    }

    protected function voteOnAttribute($attribute, $subject, TokenInterface $token)
    {
        return $this->multiFactorAuthenticationTrustResolver->isPartiallyAuthenticated($token);
    }
}
