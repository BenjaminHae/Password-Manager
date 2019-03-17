<?php

namespace App\Api;

use App\Controller\AccountController;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use OpenAPI\Server\Api\UserApiInterface;
use OpenAPI\Server\Model\AccountId;
use OpenAPI\Server\Model\ChangePassword;
use OpenAPI\Server\Model\LogonInformation;
use OpenAPI\Server\Model\Registration;
use OpenAPI\Server\Model\RegistrationInformation;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

class UserApi extends CsrfProtection implements UserApiInterface
{
    private $entityManager;
    private $passwordEncoder;
    private $security;
    private $session;
    private $accountsController;

    public function __construct(EntityManagerInterface $entityManager, UserPasswordEncoderInterface $passwordEncoder, Security $security, SessionInterface $session, CsrfTokenManagerInterface $csrfManager)
    {
        parent::__construct($csrfManager);
        $this->entityManager = $entityManager;
        $this->passwordEncoder = $passwordEncoder;
        $this->security = $security;
        $this->session = $session;
    }

    private function getAccountsController()
    {
        if (!$this->accountsController)
        {
            $this->accountsController = new AccountController($this->entityManager);
        }
        return $this->accountsController;
    }

    // ...

    public function loginUser(LogonInformation $body, &$responseCode, array &$responseHeaders) {
        $currentUser = $this->security->getUser();
        if ($currentUser)
        {
            $username = $currentUser->getUsername();
            return ["success"=> true, "loggedInAs" => $username];
        }
        return ["error" => "not logged in"];
    }

    public function logoutUser(&$responseCode, array &$responseHeaders) 
    {
        //not working, session stays active
        $this->session->start();
        $this->session->clear();
        $this->session->invalidate();
        return ["Logged Out" => true];
    }

    public function registerUser(RegistrationInformation $registration, &$responseCode, array &$responseHeaders) {
	$user = new User();
        $user->setUsername($registration->getUsername());
        $user->setEmail($registration->getEmail());
        $user->setPassword($this->passwordEncoder->encodePassword($user, $registration->getPassword()));
        $this->entityManager->persist($user);
        $this->entityManager->flush();
        return ["success" => true];
    }

    public function changePassword(ChangePassword $changes, &$responseCode, array &$responseHeaders)
    {
        $currentUser = $this->security->getUser();
        $newHash = $this->passwordEncoder->encodePassword($currentUser, $changes->getNewPassword());
        $currentUser->setPassword($newHash);
        $this->getAccountsController()->updateAccountsFromApi($currentUser, $changes->getAccounts());
        $this->entityManager->flush();
        return $this->getAccountsController()->getAccountsForUserAsAPI($currentUser);
    }

    // ...
}
