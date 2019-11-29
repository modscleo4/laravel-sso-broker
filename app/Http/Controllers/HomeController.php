<?php

namespace App\Http\Controllers;

use App\Auth;
use Illuminate\Contracts\Support\Renderable;

class HomeController extends Controller
{
    public function frontPage()
    {
        return view('index');
    }

    /**
     * Show the application dashboard.
     *
     * @return Renderable
     */
    public function index()
    {
        $user = Auth::user();
        if ($user->password_change_at == null) {
            //return redirect()->route('usuario.senha.editar');
        }

        $data = ['user' => $user];

        return view('home')->with($data);
    }
}
