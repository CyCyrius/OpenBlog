<?php

namespace App\Controller;

use App\Form\RequestResetPasswordForm;
use App\Form\ResetPasswordForm;
use App\Repository\UsersRepository;
use App\Service\JWTService;
use App\Service\SendEmailService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class SecurityController extends AbstractController
{
    #[Route(path: '/login', name: 'app_login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        
        // if ($this->getUser()){
        //     return $this->redirectToRoute('target_path');
        // }

        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();

        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', [
            'last_username' => $lastUsername,
            'error' => $error,
        ]);
    }

    #[Route(path: '/logout', name: 'app_logout')]
    public function logout(): void
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }

    #[Route(path: '/mot-de-passe-oublie', name: 'app_request_forgotten_password')]
    public function forgottenPassword(Request $request, UsersRepository $usersRepository, JWTService $jwt, SendEmailService $mail):Response
    {
        $form = $this->createForm(RequestResetPasswordForm::class);

        $form->handleRequest($request);

        if($form->isSubmitted() && $form->isValid()) {
            // Formulaire envoyé
            // Recup User
            $user = $usersRepository->findOneByEmail($form->get('email')->getData());
            // Verif si user
            if($user){
                // User existe
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

                // Génération de l'URL vers app_reset_password
                $url = $this->generateUrl('app_reset_password', ['token' => $token], UrlGeneratorInterface::ABSOLUTE_URL);

                //Envoyer l'e-mail
                $mail->send(
                    'no-reply@openblog.fr',
                    $user->getEmail(),
                    'Récupération de votre mot de passe sur le site OpenBlog',
                    'reset_password',
                    compact('user', 'url')
                );

                $this->addFlash('success', 'Email envoyé avec succès');
                return $this->redirectToRoute('app_login'); 

            }
            // $user null
            $this->addFlash('danger', 'Un problème est survenu');
            return $this->redirectToRoute('app_login'); 
        }

        return $this->render('security/request_reset_password.html.twig', [
            'requestPassForm' => $form->createView()
        ]);
    }

    #[Route(path: '/mot-de-passe-oublie/{token}', name: 'app_reset_password')]
    public function resetPassword($token, JWTService $jwt, UsersRepository $usersRepository, Request $request, UserPasswordHasherInterface $passwordHasher, EntityManagerInterface $em): Response
    {
        // Verif validité (cohérent/expiration/signature)
        if($jwt->isValid($token) && !$jwt->isExpired($token) && $jwt->check($token, $this->getParameter('app.jwtsecret'))){
            //token valide recup données (payload)
            $payload = $jwt->getPayload($token);
            // dd($payload);

            //On recup le user
            $user = $usersRepository->find($payload['user_id']);

            if($user){
                $form = $this->createForm(ResetPasswordForm::class);
                
                $form->handleRequest($request);

                if($form->isSubmitted() && $form->isValid()) {
                    $user->setPassword($passwordHasher->hashPassword($user, $form->get('password')->getData()));

                    $em->flush();

                    $this->addFlash('success', 'Mot de passe modifé avec succès');
                    return $this->redirectToRoute('app_login');
                }

                return $this->render('security/reset_password.html.twig', [
                    'passForm' => $form->createView()
                ]);
            }
        }
        $this->addFlash('danger', 'Le token est invalide ou a expiré');
        return $this->redirectToRoute('app_login');
    }

}
