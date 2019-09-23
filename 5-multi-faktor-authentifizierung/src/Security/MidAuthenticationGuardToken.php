<?php

declare(strict_types=1);

namespace App\Security;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Guard\Token\GuardTokenInterface;

final class MidAuthenticationGuardToken extends AbstractToken implements GuardTokenInterface
{
    public function __construct(UserInterface $user)
    {
        parent::__construct();
        $this->setUser($user);
        $this->setAuthenticated(true);
    }

    public function getCredentials()
    {
        return [];
    }
}
