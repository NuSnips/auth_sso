# Laravel SSO with Sanctum & Spatie Permission - DDD Implementation

## Prerequisites

-   Laravel 12+ installed
-   Composer
-   Database (MySQL/PostgreSQL)

## Project Setup

```bash
composer create-project laravel/laravel sso-system
cd sso-system
composer require laravel/sanctum
composer require spatie/laravel-permission

php artisan vendor:publish --provider="Laravel\Sanctum\SanctumServiceProvider"
php artisan vendor:publish --provider="Spatie\Permission\PermissionServiceProvider"
php artisan migrate
```

---

## Iteration 1: Core Domain Structure with Spatie Integration

### 1.1 Directory Structure

```
app/
├── Domain/
│   ├── Shared/
│   │   ├── ValueObjects/
│   │   └── Exceptions/
│   ├── User/
│   │   ├── Models/
│   │   ├── Services/
│   │   └── Events/
│   ├── Authentication/
│   │   ├── Services/
│   │   └── Events/
│   └── Authorization/
│       ├── Services/
│       └── Policies/
├── Infrastructure/
│   └── Services/
└── Application/
    ├── Services/
    └── DTOs/
```

### 1.2 Simplified Value Objects (Optional UserId)

**app/Domain/Shared/ValueObjects/Email.php**

```php
<?php

namespace App\Domain\Shared\ValueObjects;

use InvalidArgumentException;

final readonly class Email
{
    public function __construct(
        private string $value
    ) {
        $this->validate($value);
    }

    private function validate(string $email): void
    {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new InvalidArgumentException('Invalid email format');
        }
    }

    public function getValue(): string
    {
        return $this->value;
    }

    public function __toString(): string
    {
        return $this->value;
    }

    public function equals(Email $other): bool
    {
        return $this->value === $other->value;
    }
}
```

### 1.3 User Model with Spatie Integration

**app/Domain/User/Models/User.php**

```php
<?php

namespace App\Domain\User\Models;

use App\Domain\Shared\ValueObjects\Email;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
use Spatie\Permission\Traits\HasRoles;
use Illuminate\Support\Str;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable, HasRoles;

    protected $keyType = 'string';
    public $incrementing = false;

    protected $fillable = [
        'id',
        'name',
        'email',
        'password',
        'is_active',
        'email_verified_at',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected $casts = [
        'email_verified_at' => 'datetime',
        'is_active' => 'boolean',
        'password' => 'hashed',
    ];

    protected static function boot()
    {
        parent::boot();

        static::creating(function ($model) {
            if (!$model->id) {
                $model->id = (string) Str::uuid();
            }
        });
    }

    public static function createUser(
        string $name,
        Email $email,
        string $password
    ): self {
        return self::create([
            'name' => $name,
            'email' => $email->getValue(),
            'password' => $password,
            'is_active' => true,
        ]);
    }

    public function getEmail(): Email
    {
        return new Email($this->email);
    }

    public function activate(): void
    {
        $this->is_active = true;
        $this->save();
    }

    public function deactivate(): void
    {
        $this->is_active = false;
        $this->tokens()->delete();
        $this->save();
    }

    public function isActive(): bool
    {
        return $this->is_active;
    }

    // Spatie Permission helper methods
    public function getAllPermissionNames(): array
    {
        return $this->getAllPermissions()->pluck('name')->toArray();
    }

    public function getRoleNames(): array
    {
        return $this->getRoleNames();
    }
}
```

---

## Iteration 2: Authentication Service with Spatie

### 2.1 Authentication Service

**app/Domain/Authentication/Services/AuthenticationService.php**

```php
<?php

namespace App\Domain\Authentication\Services;

use App\Domain\Shared\ValueObjects\Email;
use App\Domain\User\Models\User;
use App\Domain\Authentication\Events\UserLoggedIn;
use App\Domain\Authentication\Events\UserLoggedOut;
use Illuminate\Support\Facades\Auth;
use Laravel\Sanctum\PersonalAccessToken;

class AuthenticationService
{
    public function authenticate(Email $email, string $password): ?User
    {
        $user = User::where('email', $email->getValue())->first();

        if (!$user || !$user->isActive()) {
            return null;
        }

        if (!Auth::attempt(['email' => $email->getValue(), 'password' => $password])) {
            return null;
        }

        event(new UserLoggedIn($user));

        return $user;
    }

    public function createToken(User $user, string $deviceName = 'web'): string
    {
        // Get user permissions for token abilities
        $permissions = $user->getAllPermissionNames();

        // Revoke existing tokens for this device
        $user->tokens()->where('name', $deviceName)->delete();

        // Create token with permissions as abilities
        return $user->createToken($deviceName, $permissions)->plainTextToken;
    }

    public function revokeToken(string $token): bool
    {
        $accessToken = PersonalAccessToken::findToken($token);

        if (!$accessToken) {
            return false;
        }

        $user = $accessToken->tokenable;
        $accessToken->delete();

        event(new UserLoggedOut($user));

        return true;
    }

    public function revokeAllTokens(User $user): void
    {
        $user->tokens()->delete();
        event(new UserLoggedOut($user));
    }

    public function validateToken(string $token): ?User
    {
        $accessToken = PersonalAccessToken::findToken($token);

        if (!$accessToken) {
            return null;
        }

        $user = $accessToken->tokenable;

        if (!$user->isActive()) {
            $accessToken->delete();
            return null;
        }

        return $user;
    }
}
```

---

## Iteration 3: Simplified Authorization Service

### 3.1 Authorization Service (Wrapper for Spatie)

**app/Domain/Authorization/Services/AuthorizationService.php**

```php
<?php

namespace App\Domain\Authorization\Services;

use App\Domain\User\Models\User;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Illuminate\Support\Collection;

class AuthorizationService
{
    public function userHasPermission(User $user, string $permission): bool
    {
        return $user->hasPermissionTo($permission);
    }

    public function userHasRole(User $user, string $role): bool
    {
        return $user->hasRole($role);
    }

    public function userHasAnyRole(User $user, array $roles): bool
    {
        return $user->hasAnyRole($roles);
    }

    public function assignPermissionToUser(User $user, string $permission): void
    {
        $user->givePermissionTo($permission);
    }

    public function removePermissionFromUser(User $user, string $permission): void
    {
        $user->revokePermissionTo($permission);
    }

    public function assignRoleToUser(User $user, string $role): void
    {
        $user->assignRole($role);
    }

    public function removeRoleFromUser(User $user, string $role): void
    {
        $user->removeRole($role);
    }

    public function syncUserRoles(User $user, array $roles): void
    {
        $user->syncRoles($roles);
    }

    public function syncUserPermissions(User $user, array $permissions): void
    {
        $user->syncPermissions($permissions);
    }

    public function getUserPermissions(User $user): Collection
    {
        return $user->getAllPermissions();
    }

    public function getUserRoles(User $user): Collection
    {
        return $user->getRoles();
    }

    public function canAccessResource(User $user, string $resource, string $action): bool
    {
        return $user->hasPermissionTo("{$resource}.{$action}");
    }

    public function createPermission(string $name, ?string $guardName = null): Permission
    {
        return Permission::create([
            'name' => $name,
            'guard_name' => $guardName ?? 'web'
        ]);
    }

    public function createRole(string $name, ?string $guardName = null): Role
    {
        return Role::create([
            'name' => $name,
            'guard_name' => $guardName ?? 'web'
        ]);
    }

    public function assignPermissionToRole(string $role, string $permission): void
    {
        $roleModel = Role::findByName($role);
        $roleModel->givePermissionTo($permission);
    }
}
```

---

## Iteration 4: SSO Service (Same as Before)

**app/Domain/Authentication/Services/SSOService.php**

```php
<?php

namespace App\Domain\Authentication\Services;

use App\Domain\User\Models\User;
use App\Domain\Authorization\Services\AuthorizationService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

class SSOService
{
    public function __construct(
        private readonly AuthenticationService $authService,
        private readonly AuthorizationService $authorizationService
    ) {}

    public function generateSSOToken(User $user, string $redirectUrl, int $ttl = 300): string
    {
        $token = Str::random(64);
        $key = "sso_token:{$token}";

        Cache::put($key, [
            'user_id' => $user->id,
            'redirect_url' => $redirectUrl,
            'created_at' => now(),
        ], $ttl);

        return $token;
    }

    public function validateSSOToken(string $token): ?array
    {
        $key = "sso_token:{$token}";
        $data = Cache::get($key);

        if (!$data) {
            return null;
        }

        $user = User::find($data['user_id']);

        if (!$user || !$user->isActive()) {
            Cache::forget($key);
            return null;
        }

        // Remove token after use (single use)
        Cache::forget($key);

        return [
            'user' => $user,
            'redirect_url' => $data['redirect_url'],
        ];
    }

    public function createSSOSession(User $user, string $clientApp): array
    {
        $sessionToken = $this->authService->createToken($user, "sso-{$clientApp}");
        $permissions = $user->getAllPermissionNames();
        $roles = $user->getRoleNames();

        return [
            'token' => $sessionToken,
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->getEmail()->getValue(),
                'is_active' => $user->isActive(),
            ],
            'permissions' => $permissions,
            'roles' => $roles,
            'expires_at' => now()->addMinutes(config('sanctum.expiration', 1440)),
        ];
    }

    public function getSSOLoginUrl(string $redirectUrl, string $clientId = null): string
    {
        $params = http_build_query([
            'redirect_url' => $redirectUrl,
            'client_id' => $clientId,
            'timestamp' => time(),
        ]);

        return route('sso.login') . '?' . $params;
    }

    public function validateRedirectUrl(string $url): bool
    {
        $allowedDomains = config('sso.allowed_redirect_domains', []);

        if (empty($allowedDomains)) {
            return true;
        }

        $parsedUrl = parse_url($url);
        $domain = $parsedUrl['host'] ?? '';

        return in_array($domain, $allowedDomains);
    }
}
```

---

## Iteration 5: Controllers with Spatie Middleware

### 5.1 Auth Controller

**app/Http/Controllers/Api/AuthController.php**

```php
<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Domain\Authentication\Services\AuthenticationService;
use App\Domain\Shared\ValueObjects\Email;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function __construct(
        private readonly AuthenticationService $authService
    ) {}

    public function login(Request $request): JsonResponse
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string|min:8',
            'device_name' => 'sometimes|string|max:255'
        ]);

        $email = new Email($request->email);
        $user = $this->authService->authenticate($email, $request->password);

        if (!$user) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        $token = $this->authService->createToken(
            $user,
            $request->device_name ?? 'web'
        );

        return response()->json([
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->getEmail()->getValue(),
                'is_active' => $user->isActive(),
                'permissions' => $user->getAllPermissionNames(),
                'roles' => $user->getRoleNames(),
            ],
            'token' => $token,
        ]);
    }

    public function logout(Request $request): JsonResponse
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json(['message' => 'No token provided'], 400);
        }

        $success = $this->authService->revokeToken($token);

        if (!$success) {
            return response()->json(['message' => 'Invalid token'], 400);
        }

        return response()->json(['message' => 'Successfully logged out']);
    }

    public function me(Request $request): JsonResponse
    {
        $user = $request->user();

        return response()->json([
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->getEmail()->getValue(),
                'is_active' => $user->isActive(),
                'permissions' => $user->getAllPermissionNames(),
                'roles' => $user->getRoleNames(),
            ],
        ]);
    }

    public function verify(Request $request): JsonResponse
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json(['valid' => false, 'message' => 'No token provided'], 400);
        }

        $user = $this->authService->validateToken($token);

        if (!$user) {
            return response()->json(['valid' => false, 'message' => 'Invalid or expired token'], 401);
        }

        return response()->json([
            'valid' => true,
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->getEmail()->getValue(),
                'is_active' => $user->isActive(),
                'permissions' => $user->getAllPermissionNames(),
                'roles' => $user->getRoleNames(),
            ],
        ]);
    }
}
```

### 5.2 User Controller with Spatie Middleware

**app/Http/Controllers/Api/UserController.php**

```php
<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Domain\User\Models\User;
use App\Domain\Shared\ValueObjects\Email;
use App\Domain\Authorization\Services\AuthorizationService;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class UserController extends Controller
{
    public function __construct(
        private readonly AuthorizationService $authorizationService
    ) {
        $this->middleware('auth:sanctum');

        // Using Spatie middleware
        $this->middleware('permission:user.read')->only(['index', 'show']);
        $this->middleware('permission:user.create')->only(['store']);
        $this->middleware('permission:user.update')->only(['update']);
        $this->middleware('permission:user.delete')->only(['destroy']);
    }

    public function index(Request $request): JsonResponse
    {
        $users = User::with(['roles', 'permissions'])->paginate(10);

        return response()->json($users);
    }

    public function store(Request $request): JsonResponse
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users',
            'password' => 'required|string|min:8',
            'roles' => 'sometimes|array',
            'permissions' => 'sometimes|array',
        ]);

        $user = User::createUser(
            $request->name,
            new Email($request->email),
            $request->password
        );

        // Assign roles if provided
        if ($request->has('roles')) {
            $this->authorizationService->syncUserRoles($user, $request->roles);
        }

        // Assign permissions if provided
        if ($request->has('permissions')) {
            $this->authorizationService->syncUserPermissions($user, $request->permissions);
        }

        return response()->json([
            'message' => 'User created successfully',
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->getEmail()->getValue(),
                'is_active' => $user->isActive(),
                'roles' => $user->getRoleNames(),
                'permissions' => $user->getAllPermissionNames(),
            ]
        ], 201);
    }

    public function show(Request $request, string $id): JsonResponse
    {
        $user = User::with(['roles', 'permissions'])->findOrFail($id);

        return response()->json([
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->getEmail()->getValue(),
                'is_active' => $user->isActive(),
                'roles' => $user->getRoleNames(),
                'permissions' => $user->getAllPermissionNames(),
            ]
        ]);
    }

    public function permissions(Request $request): JsonResponse
    {
        $user = $request->user();

        return response()->json([
            'permissions' => $user->getAllPermissionNames(),
            'roles' => $user->getRoleNames(),
        ]);
    }

    public function assignRole(Request $request, string $id): JsonResponse
    {
        $request->validate([
            'role' => 'required|string|exists:roles,name'
        ]);

        $user = User::findOrFail($id);
        $this->authorizationService->assignRoleToUser($user, $request->role);

        return response()->json(['message' => 'Role assigned successfully']);
    }

    public function removeRole(Request $request, string $id): JsonResponse
    {
        $request->validate([
            'role' => 'required|string|exists:roles,name'
        ]);

        $user = User::findOrFail($id);
        $this->authorizationService->removeRoleFromUser($user, $request->role);

        return response()->json(['message' => 'Role removed successfully']);
    }
}
```

---

## Iteration 6: Database Seeder with Spatie Models

### 6.1 Authorization Seeder

**database/seeders/SpatieAuthorizationSeeder.php**

```php
<?php

namespace Database\Seeders;

use App\Domain\User\Models\User;
use App\Domain\Shared\ValueObjects\Email;
use App\Domain\Authorization\Services\AuthorizationService;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Illuminate\Database\Seeder;

class SpatieAuthorizationSeeder extends Seeder
{
    public function run()
    {
        // Clear cache
        app()[\Spatie\Permission\PermissionRegistrar::class]->forgetCachedPermissions();

        // Create permissions
        $permissions = [
            'user.create',
            'user.read',
            'user.update',
            'user.delete',
            'role.manage',
            'permission.manage',
            'sso.manage'
        ];

        foreach ($permissions as $permission) {
            Permission::create(['name' => $permission]);
        }

        // Create roles
        $adminRole = Role::create(['name' => 'admin']);
        $userRole = Role::create(['name' => 'user']);
        $moderatorRole = Role::create(['name' => 'moderator']);

        // Assign permissions to roles
        $adminRole->givePermissionTo(Permission::all());

        $moderatorRole->givePermissionTo([
            'user.read',
            'user.update',
        ]);

        $userRole->givePermissionTo([
            'user.read',
        ]);

        // Create users
        $adminUser = User::createUser(
            'System Administrator',
            new Email('admin@example.com'),
            'password123'
        );

        $regularUser = User::createUser(
            'Regular User',
            new Email('user@example.com'),
            'password123'
        );

        $moderatorUser = User::createUser(
            'Moderator User',
            new Email('moderator@example.com'),
            'password123'
        );

        // Assign roles
        $adminUser->assignRole('admin');
        $regularUser->assignRole('user');
        $moderatorUser->assignRole('moderator');

        $this->command->info('Spatie authorization system seeded successfully!');
        $this->command->info('Admin: admin@example.com / password123');
        $this->command->info('User: user@example.com / password123');
        $this->command->info('Moderator: moderator@example.com / password123');
    }
}
```

---

## Iteration 7: Routes with Spatie Middleware

### 7.1 API Routes

**routes/api.php**

```php
<?php

use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\UserController;
use App\Http\Controllers\Api\SSOController;
use Illuminate\Support\Facades\Route;

// Public routes
Route::prefix('auth')->group(function () {
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/verify', [AuthController::class, 'verify']);
});

// SSO Routes
Route::prefix('sso')->group(function () {
    Route::post('/login', [SSOController::class, 'login']);
    Route::post('/callback', [SSOController::class, 'callback']);
    Route::get('/initiate', [SSOController::class, 'initiate']);
    Route::get('/status', [SSOController::class, 'status']);
    Route::post('/logout', [SSOController::class, 'logout']);
});

// Protected routes
Route::middleware('auth:sanctum')->group(function () {
    Route::prefix('auth')->group(function () {
        Route::post('/logout', [AuthController::class, 'logout']);
        Route::get('/me', [AuthController::class, 'me']);
    });

    Route::prefix('users')->group(function () {
        Route::get('/', [UserController::class, 'index'])
            ->middleware('permission:user.read');

        Route::post('/', [UserController::class, 'store'])
            ->middleware('permission:user.create');

        Route::get('/permissions', [UserController::class, 'permissions']);

        Route::get('/{id}', [UserController::class, 'show'])
            ->middleware('permission:user.read');

        Route::post('/{id}/roles', [UserController::class, 'assignRole'])
            ->middleware('permission:user.update');

        Route::delete('/{id}/roles', [UserController::class, 'removeRole'])
            ->middleware('permission:user.update');
    });

    // Admin only routes
    Route::middleware(['role:admin'])->group(function () {
        Route::prefix('admin')->group(function () {
            // Admin-specific endpoints
        });
    });
});
```

---

## Iteration 8: Configuration & Setup

### 8.1 Update User Migration

```php
<?php
// database/migrations/2024_01_01_000001_update_users_table.php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->uuid('id')->primary()->change();
            $table->boolean('is_active')->default(true);
            $table->index(['email', 'is_active']);
        });
    }

    public function down()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropIndex(['email', 'is_active']);
            $table->dropColumn('is_active');
        });
    }
};
```

### 8.2 Service Provider

**app/Providers/DomainServiceProvider.php**

```php
<?php

namespace App\Providers;

use App\Domain\Authentication\Services\AuthenticationService;
use App\Domain\Authorization\Services\AuthorizationService;
use App\Domain\Authentication\Services\SSOService;
use Illuminate\Support\ServiceProvider;

class DomainServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->singleton(AuthenticationService::class);
        $this->app->singleton(AuthorizationService::class);
        $this->app->singleton(SSOService::class);
    }

    public function boot()
    {
        // Spatie already registers its middleware
        // No need to register additional permission middleware
    }
}
```

### 8.3 Configuration Updates

**config/permission.php** (Customize if needed)

```php
<?php

return [
    'models' => [
        'permission' => Spatie\Permission\Models\Permission::class,
        'role' => Spatie\Permission\Models\Role::class,
    ],

    'table_names' => [
        'roles' => 'roles',
        'permissions' => 'permissions',
        'model_has_permissions' => 'model_has_permissions',
        'model_has_roles' => 'model_has_roles',
        'role_has_permissions' => 'role_has_permissions',
    ],

    'column_names' => [
        'role_pivot_key' => null,
        'permission_pivot_key' => null,
        'model_morph_key' => 'model_id',
        'team_foreign_key' => 'team_id',
    ],

    'register_permission_check_method' => true,
    'register_octane_reset_listener' => false,
    'teams' => false,
    'use_passport_client_credentials' => false,
    'display_permission_in_exception' => false,
    'display_role_in_exception' => false,
    'enable_wildcard_permission' => false,
    'cache' => [
        'expiration_time' => \DateInterval::createFromDateString('24 hours'),
        'key' => 'spatie.permission.cache',
        'store' => 'default',
    ],
];
```

---

## Setup Commands

```bash
# Install packages
composer require spatie/laravel-permission

# Publish configurations
php artisan vendor:publish --provider="Spatie\Permission\PermissionServiceProvider"

# Register service provider (add to config/app.php)
App\Providers\DomainServiceProvider::class,

# Run migrations
php artisan migrate

# Seed data
php artisan db:seed --class=SpatieAuthorizationSeeder

# Clear permission cache
php artisan permission:cache-reset

# Start server
php artisan serve
```

---

## Key Benefits of Spatie Integration

1. **Less Code**: Eliminated custom Permission/Role models and relationships
2. **Better Performance**: Built-in caching and query optimization
3. **Rich Features**: Middleware, Blade directives, artisan commands
4. **Maintained**: Regular updates and bug fixes by Spatie
5. **Laravel Integration**: Works seamlessly with Gates, Policies
6. **Flexibility**: Support for teams, wildcards, custom guards

## Spatie Features You Get

-   `$user->hasPermissionTo('user.create')`
-   `$user->hasRole('admin')`
-   `@can('user.create')` in Blade
-   `Route::middleware('permission:user.read')`
-   `Route::middleware('role:admin')`
-   Automatic caching of permissions
-   Artisan commands for management

This approach gives you enterprise-grade permission management with minimal custom code!
