<?php
declare(strict_types=1);

namespace App\Security;


use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

final class VerificationCodeBroker
{
    private const ATTRIBUTE_KEY = 'verification-code';

    public function generateFor(TokenInterface $token): string
    {
        $code = (string) random_int(10000, 99999);
        $token->setAttribute(self::ATTRIBUTE_KEY, $code);

        return $code;
    }

    public function check(TokenInterface $token, string $code): bool
    {
        if (!$token->hasAttribute(self::ATTRIBUTE_KEY)) {
            return false;
        }

        return $token->getAttribute(self::ATTRIBUTE_KEY) === $code;
    }
}
