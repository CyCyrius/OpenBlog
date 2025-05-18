<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use App\Entity\Users;

final class MainController extends AbstractController
{
    #[Route('/', name: 'app_main')]
    public function index(): Response
    {
        if( $this->getUser() ) {
            return $this->render('main/index.html.twig');
        } else {
            return $this->render('main/index.html.twig', [
            'user' => 'Anonymous',
        ]);
        }


    }

    #[Route('/mentions-legales', name: 'app_mentions')]
    public function mentions(): Response
    {
        return $this->render('main/mentions.html.twig');
    }

}
