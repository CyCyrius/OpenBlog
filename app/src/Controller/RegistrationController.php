<?php

namespace App\Controller;

use App\Entity\Users;
use App\Form\RegistrationForm;
use App\Repository\UsersRepository;
use App\Service\JWTService;
use App\Service\SendEmailService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;

class RegistrationController extends AbstractController
{
    #[Route('/register', name: 'app_register')]
    public function register(Request $request, UserPasswordHasherInterface $userPasswordHasher, Security $security, EntityManagerInterface $entityManager, JWTService $jwt, SendEmailService $mail): Response
    {
        $user = new Users();
        $form = $this->createForm(RegistrationForm::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            /** @var string $plainPassword */
            $plainPassword = $form->get('plainPassword')->getData();

            // encode the plain password
            $user->setPassword($userPasswordHasher->hashPassword($user, $plainPassword));

            $entityManager->persist($user);
            $entityManager->flush();

            // do anything else you need here, like send an email

            // Creation du Token
            // --- Header
            $header = [
                'typ'=>'JWT',
                'alg'=>'HS256'
            ];
            // --- Payload
            $payload = [
                'user_id'=>$user->getId()
            ];
            // --- Generation
            $token = $jwt->generate($header, $payload, $this->getParameter('app.jwtsecret'));
            // dd($token);

            //Envoyer l'e-mail
            $mail->send(
                'no-reply@openblog.fr',
                $user->getEmail(),
                'Activation de votre compte',
                'register',
                compact('user', 'token') //['user'=>$user, 'token'=>$token]
            );

            $this->addFlash('success', 'Utilisateur inscrit(e), veuillez cliquer sur le lien reçu pour confirmer votre adresse e-mail');

            return $security->login($user, 'form_login', 'main');
        }

        return $this->render('registration/register.html.twig', [
            'registrationForm' => $form,
        ]);
    }

    #[Route('/verify/{token}', name: 'app_verify_user')]
    public function verifUser($token, JWTService $jwt, UsersRepository $usersRepository, EntityManagerInterface $em):Response 
    {
        //Verif validité (cohérent/expiration/signature)
        if($jwt->isValid($token) && !$jwt->isExpired($token) && $jwt->check($token, $this->getParameter('app.jwtsecret'))){
            //token valide recup données (payload)
            $payload = $jwt->getPayload($token);
            // dd($payload);

            //On recup le user
            $user = $usersRepository->find($payload['user_id']);

            //Verif user et pas deja activé
            if($user && !$user->isVerified()){
                $user->setIsVerified(true);
                $em->flush();

                $this->addFlash('success', 'Utilisateur activé');
                return $this->redirectToRoute('app_main');
            }
        }
        $this->addFlash('danger', 'Le token est invalide ou a expiré');
        return $this->redirectToRoute('app_login');
    }

}
