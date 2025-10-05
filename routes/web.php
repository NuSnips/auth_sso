<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});


// Route::get('/mail-test', function () {
//     Mail::raw('This is a test email sent via Mailpit!', function ($message) {
//         $message->to('test@mailpit.test')
//             ->subject('Mailpit Test');
//     });
//     return 'Test email sent!';
// });
