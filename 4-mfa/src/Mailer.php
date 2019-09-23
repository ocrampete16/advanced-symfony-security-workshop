<?php
declare(strict_types=1);

namespace App;


use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

final class Mailer
{
    private $mailer;

    public function __construct(\Swift_Mailer $mailer)
    {
        $this->mailer = $mailer;
    }

    public function sendCodeVerificationMail(TokenInterface $token, string $code): void
    {
        $message = (new \Swift_Message('Your Email Code'))
            ->setFrom('no-reply@symfonydemo.com')
            ->setTo(sprintf('%s@example.com', $token->getUsername()))
            ->setBody(sprintf('You email code is: %s', $code));

        $this->mailer->send($message);
    }
}
