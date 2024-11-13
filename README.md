# Django-Advanced

An advanced exploration of Django concepts and best practices, developed as part of my course at [SoftUni](https://softuni.bg/). This repository includes sophisticated examples, tools, and patterns for building more robust, scalable, and secure Django applications.

[Click here for more information about the course](https://softuni.bg/trainings/4714/django-advanced-october-2024)

![brecht-corbeel-qHx3w6Gwz9k-unsplash](https://github.com/user-attachments/assets/e58e987a-7536-42dc-9769-a86e61fc783c)


## 01.Authentication and Autorization


**1. The Identity in the Web**

В контекста на уеб приложенията, „идентичност“ представлява начина, по който уеб услугите разпознават и различават потребителите. Когато потребителят влезе в сайт, той има своя идентичност в системата — набор от уникални характеристики, като потребителско име и парола, които го отличават от останалите.

**Примери на идентификационни атрибути:**

- ```username``` — уникален идентификатор за потребителя.
- ```password``` — защитен низ, с който се валидира неговата идентичност.
- ```email``` — алтернативен атрибут за идентификация.

**2. Authentication**

Authentication е процесът, чрез който потвърждаваме, че потребителят е този, за когото се представя. Това става чрез проверка на идентификационните данни — например, въвеждане на правилни потребителско име и парола.

**Основни концепции в удостоверяването:**

- Credentials: Комбинацията от потребителско име и парола или алтернативни методи като OTP (One-Time Password).
- Sessions: След успешен вход, на потребителя му се създава сесия, която поддържа състоянието на неговия вход в сайта.

**Пример за удостоверяване с Python:**

```
def authenticate_user(username, password):
    if username == "user1" and password == "password123":
        return True
    return False

is_authenticated = authenticate_user("user1", "password123")
print("Authenticated" if is_authenticated else "Not authenticated")
```

**3. Authentication in Django**

Django има вградена система за удостоверяване, която опростява процеса и използва готови функции и middleware.

**Основни компоненти:**

- **User Model**: Django предоставя ```User``` модел по подразбиране, който съдържа основни полета като ```username```, ```password```, ```email```.
- **Authentication Functions**: ```authenticate()``` и ```login()``` са основни функции в ```Django```, които проверяват дали потребителят е валиден и създават сесия.

**Пример за използване на Django функционалност:**

```
from django.contrib.auth import authenticate, login

def user_login(request):
    username = request.POST['username']
    password = request.POST['password']
    user = authenticate(request, username=username, password=password)
    if user is not None:
        login(request, user)
        return "User logged in successfully"
    else:
        return "Invalid credentials"
```

Тук ```authenticate()``` проверява потребителското име и паролата, а ```login()``` създава сесия, която следи потребителя по време на престоя му в сайта.

**4. Permissions and Authorization**
Authorization (авторизация) определя какви действия има право да изпълнява потребителят след като е удостоверен.

**Основни концепции:**

- Permissions (Разрешения): Дефинират какви действия може да изпълнява потребителят, напр. четене, писане, изтриване.
- Groups (Групи): Потребителите могат да бъдат групирани, и така се определят групови разрешения.

**Пример за разрешения в Django:**

```
from django.contrib.auth.decorators import permission_required

@permission_required('app_name.view_model')
def view_model(request):
    # Logic here for viewing the model
    return "Model view accessed"
```

Функцията ```permission_required``` проверява дали потребителят има специфично разрешение (```view_model``` в този случай) за достъп до определени ресурси.

**5. Web Security**

Уеб сигурността е ключов аспект при управление на удостоверяване и авторизация. Основни мерки за защита:

- **Hashing на пароли**: Django използва хеширане на паролите с помощта на алгоритми като PBKDF2 и Argon2.
- **CSRF защита**: Защита срещу Cross-Site Request Forgery (CSRF) атаки чрез csrf_token при всяка POST заявка.
- **XSS защита**: Django автоматично избягва XSS (Cross-Site Scripting) атаки, като изпълнява escaping на потенциално опасен HTML в шаблоните.

**Пример за CSRF защита:**

Django автоматично добавя CSRF защита при формите. В шаблоните, csrf_token гарантира, че заявката е легитимна:

```
<form method="post">
  {% csrf_token %}
  <input type="text" name="username">
  <input type="password" name="password">
  <button type="submit">Login</button>
</form>
```
**ВИДОВЕ АТАКИ:**

**SQL инжекция (SQL Injection)**

  - SQL инжекцията е атака, при която злонамерен потребител въвежда зловреден SQL код в полета за въвеждане на данни (като форми за логин), с цел да манипулира или извлече данни от базата данни. Тази уязвимост възниква, когато приложението не валидира или не пречиства потребителския вход правилно.

**Кроссайт скриптиране (XSS)**

  - Кроссайт скриптирането е атака, при която злонамерен потребител вкарва зловреден скрипт (обикновено JavaScript) в уебсайт, който след това се изпълнява от браузъра на други потребители. Това може да доведе до кражба на бисквитки, манипулация на съдържание или пренасочване към зловредни сайтове.

**URL/HTTP манипулационни атаки (Промяна на параметри - Parameter Tampering)**

  - При този вид атака, нападателят манипулира URL и ли параметри в HTTP заявка, за да получи неоторизиран достъп до ресурси или да промени поведението на приложението. Например, промяна на параметър в URL, който определя цената на продукт, за да се закупи нещо на по-ниска цена.

**Кроссайт заявка за фалшификация (CSRF)**

  - CSRF атаката принуждава потребител, който е логнат в уеб приложение, да извърши неволно действие (като изпращане на форма или извършване на плащане), без неговото знание. Това се постига чрез изпращане на специално създадена връзка или форма към потребителя.

**Атаки с груба сила (Brute Force Attacks) и DDoS (Разпределени атаки за отказ от услуга)**

  - При атака с груба сила, нападателят автоматично опитва множество комбинации от пароли или ключове, докато не намери правилната. DDoS атаките целят да претоварят уебсайт или услуга с огромен брой заявки, което да доведе до забавяне или пълно прекъсване на услугата.

**Недостатъчен контрол на достъпа (Insufficient Access Control)**

  - Недостатъчният контрол на достъпа е уязвимост, при която потребители или системи получават достъп до ресурси или функционалности, за които нямат разрешение. Това може да доведе до изтичане на конфиденциална информация или изпълнение на неоторизирани действия.

**Липса на SSL (HTTPS) / Атаки Човек в средата (MITM)**

  - Липсата на SSL (HTTPS) прави връзката между потребителя и уебсайта незащитена, което позволява на нападател да прихване, промени или открадне данни (като пароли или лична информация) по време на предаването. MITM атаката възниква, когато нападателят се позиционира между комуникиращите страни и тайно следи или манипулира комуникацията.

**Фишинг/Социално инженерство (Phishing/Social Engineering)**

  - Фишингът и социалното инженерство са методи, при които нападателят измамно убеждава потребителя да разкрие чувствителна информация, (като пароли или номера на кредитни карти), или да извърши определено действие, (като инсталиране на зловреден софтуер), като се представя за доверено лице или организация.

---

## 02.User Model and Password Management

**1. User Model in Django**

**Основни атрибути:**

- **username**: Задължително, до 150 символа.
- **password**: Задължително, но съхранено по сигурен начин (хеширано).
- **email, first_name, last_name**: По желание.

**Специални флагове:**

- **is_staff** и **is_superuser**: За потребители с административни права.
- **is_active**: Показва дали потребителят е активен.

**Методи:**

- ```get_username()```: Връща потребителското име.
- ```is_authenticated:``` Проверява дали потребителят е вписан.

**Достъп до модела:**

```
from django.contrib.auth import get_user_model
UserModel = get_user_model()
```

**2.Създаване и автентикация на потребители:**

```
# Създаване на потребител
new_user = UserModel.objects.create_user('peter', 'peter@gmail.com', 'password123')

# Автентикация
from django.contrib.auth import authenticate
user = authenticate(username='peter', password='password123')
```

- Може да бъде намерен в моделите на django.auth app-a
- Таблица auth_users
- Имаме го във всяка заявка и можем да го достъпим с request.user
- Django ни позволява да променяме вградения потребителски модел на няколко нива
  - Можем само да го надградим наследявайки ```AbstractUser``` или изцяло да го заменим наследявайки ```AbstractBaseUser```
 
- Дава ни PermissionsMixin, който вграденият User модел наследява.
  - Той се грижи за това дали потребителя е superuser, какви права има и в какви групи е.
  - Дава ни **staff_member_required** декоратор.
- ```USERNAME_FIELD``` ни позволява да презапишем полето, което ще се използва за първи креденшъл.
- ```email_user()``` ни позволява да изпращаме имейли на потребителите след настройка на SMTP.
- ```AnonymusUser```, който не е модел, но клас, който презаписва всички атрибути на базовия клас.
 
- Дава ни 2 основни функции:
  - ```login``` - закача cookie за аутентикирания потребител.
  - ```authenticate``` - проверява дали креденшълите на потребителя са верни.
 
**3.Login/Logout**

- **LoginView** и **LogoutView**: Вградени изгледи за обработка на вписване и излизане на потребители.
  
  ```
      # urls.py
    from django.contrib.auth import views as auth_views
    
    urlpatterns = [
        path('login/', auth_views.LoginView.as_view(), name='login'),
        path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    ]
  ```
- **Пренасочване**: Настройки LOGIN_REDIRECT_URL и LOGOUT_REDIRECT_URL в settings.py управляват пренасочванията след вписване/излизане.

- **next** - помага ни да редиректнем потребителя към view-то, което се е опитал да достъпи преди да е бил логнат.
- **site** - url-a на уебсайта

**4.Register**

- Нямаме view за регистрация, но имаме форма.
  
  ```
  class UserRegisterView(CreateView):
    form_class = UserCreationForm
    template_name = 'registration/register.html'
    success_url = reverse_lazy('login')


    # settings.py - optional
    LOGIN_REDIRECT_URL = '/'
    LOGOUT_REDIRECT_URL = '/'
    
     <form method="post" action="{% url 'login' %}{% if next %}?next={{ next }}{% endif %}">
      {% csrf_token %}
      {{ form.as_p }}
      <button type="submit">Login</button>
     </form>
  ```

- **UserCreationForm**: Вградената форма в Django за регистрация на потребители с полета като ```username```, ```password```
- **Собствени форми за регистрация**: Разширяване на полетата (например добавяне на ```email```), чрез създаване на наследен клас от ```UserCreationForm```.

 ```
    from django.contrib.auth.forms import UserCreationForm
    
    class CustomRegistrationForm(UserCreationForm):
        email = models.EmailField(required=True)
    
        class Meta:
            model = UserModel
            fields = ('username', 'email', 'first_name', 'last_name')
    
    def save(self, commit=True):
    # clean the data and save the user
 ```

**4.Password Management**

- **Механизъм за сигурност**: Django използва PBKDF2 алгоритъм със SHA256 за хеширане на пароли, което ги прави устойчиви на атаки.
- **Хеширащи алгоритми:**
  - Възможности като PBKDF2, Argon2 и bcrypt са част от PASSWORD_HASHERS за сигурно хеширане.
  - За тестове може да се използва по-бърз хеширащ алгоритъм (например MD5), но не е подходящ за продукционни среди.
- **Задаване на пароли:**
  
  ```
  user.set_password('new_password')  # Сигурно хешира и задава нова парола.
  ```

- **Проверка на пароли:**

  ```
  user.check_password('entered_password')  # Проверява въведена от потребителя парола.
  ```

**5.Groups**

- **Права на достъп**: CRUD права на достъп (```add```, ```change```, ```delete```, ```view```) се създават автоматично за всеки модел.
- **Групи**: Улесняват управлението на права на достъп за множество потребители.
- **Използване:**

  ```
  from django.contrib.auth.models import Group
  group = Group.objects.create(name='Editors')
  ```

  ---

## 03.Extending the User Model

В Django, User моделът е основен компонент, който се използва за управление на потребителски данни. В някои случаи обаче може да се наложи добавяне на нови функционалности или специфична логика. Django позволява разширяване на User модела по няколко начина, като всяка техника има своите предимства и недостатъци.

```AUTH_USER_MODEL = 'path.to.my.model'```

**01.User Model Inheritance Chain**

Django предоставя няколко класа, които служат като основа за изграждане на User модели:

- **User**: Базовият клас, който не добавя нови полета или методи.

- **AbstractUser**: Добавя полета като ```username```, ```first_name```, ```last_name```, и ```email```.

- **AbstractBaseUser**: Съдържа два метода ```password``` и ```last_login```.

- **PermissionsMixin**: Удобен миксин за управление на права и роли на потребителите.

Наследяваме **AbstractUser**, защото, когато наследим неабстрактен модел, получаваме **One to One relationship**, докато, ако е абстрактен, получаваме директно полетата в една таблица.

<img width="1267" alt="Screenshot 2024-11-09 at 22 18 24" src="https://github.com/user-attachments/assets/d76efa8b-f3d2-4c9d-8047-c6e79958f108">

**02.Extending the User Model**

Django предлага няколко подхода за разширяване на User модела, като изборът на метод зависи от нуждите на приложението:

**2.1.Proxy модел**

**Proxy моделът** е подход за промяна на поведението на съществуващ модел без да се променя базата данни. Използва се, ако искаме да добавим методи или промяна на сортирането, но без да създаваме нови полета.

```
from django.contrib.auth.models import User

class AppUserProxy(User):
    class Meta:
        proxy = True
        ordering = ('first_name', )

    def some_custom_behavior(self):
        # Добавяме поведение специфично за AppUserProxy
        pass
```
**2.2.One-to-One релация**

Тази техника позволява създаване на допълнителна таблица в базата данни, където можем да съхраняваме информация, специфична за потребителя, без да променяме съществуващата ```auth_user``` таблица.

```
from django.contrib.auth import get_user_model
from django.db import models

UserModel = get_user_model()

class Profile(models.Model):
    user = models.OneToOneField(UserModel, on_delete=models.CASCADE, primary_key=True)
    date_of_birth = models.DateField(null=True, blank=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', null=True, blank=True)

    def __str__(self):
        return self.user.username
```
Така всяка ```Profile``` инстанция се свързва директно с User модела чрез One-to-One релация.

**2.3. Наследяване на AbstractUser**

С този подход можем директно да добавим нови полета към User модела, без да създаваме нова таблица. Трябва обаче да променим настройката ```AUTH_USER_MODEL``` в ```settings.py```.

```
from django.contrib.auth import models as auth_models

class CustomUser(auth_models.AbstractUser):
    date_of_birth = models.DateField(null=True, blank=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    # Други допълнителни полета
```
**2.4. Наследяване на AbstractBaseUser**

Най-напредналата техника, която позволява пълна свобода при дефиниране на User модела, включително и уникални изисквания за аутентификация.

```
from django.contrib.auth import models as auth_models
from django.db import models

class AppUser(auth_models.AbstractBaseUser, auth_models.PermissionsMixin):
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email
```
**03. Управление на потребителите чрез BaseUserManager**

При наследяване от ```AbstractBaseUser```, е препоръчително да създадем ```BaseUserManager```, който да управлява създаването на потребители и суперпотребители.

```
from django.contrib.auth.models import BaseUserManager

class AppUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)
```

**04. Django Signals**

Сигналите са начин за реагиране на събития в приложението, без да се променя основният код. Например, при създаване на нов потребител, можем автоматично да създадем свързан профил чрез сигнал.

```
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver

UserModel = get_user_model()

@receiver(post_save, sender=UserModel)
def create_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)
```

**05. AppUser Forms**

Формите за създаване и редактиране на потребители в Django са важна част от работата с потребителски данни. При създаването на персонализиран User модел, трябва да създадем и персонализирани форми, за да можем да управляваме потребителите през Django Admin интерфейса.

**Пример за AppUserCreationForm и AppUserChangeForm**
В този случай създаваме форми за създаване на нови потребители ```AppUserCreationForm``` и за промяна на съществуващи потребители ```AppUserChangeForm```.

```
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.contrib.auth import get_user_model

UserModel = get_user_model()

class AppUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = UserModel
        fields = ('email',)  # Изброяваме полетата, които искаме да покажем

class AppUserChangeForm(UserChangeForm):
    class Meta(UserChangeForm.Meta):
        model = UserModel
        fields = '__all__'  # Покажете всички полета за редактиране на потребителите
```
- **AppUserCreationForm**: Използва се при създаването на нови потребители и задава кои полета да се показват в admin интерфейса.

- **AppUserChangeForm**: Използва се за промяна на съществуващи потребители и определя кои полета могат да се редактират.

**06. Регистриране на AppUser в Admin сайта**

След като сме създали новия потребителски модел и формите, трябва да регистрираме ```AppUser``` модела в ```Django Admin```, за да може да се управлява през администраторския панел. Това включва настройка на изгледа и полетата, които ще се показват.

**Пример за регистрация на AppUser в Django Admin**

```
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth import get_user_model
from .forms import AppUserCreationForm, AppUserChangeForm

UserModel = get_user_model()

@admin.register(UserModel)
class AppUserAdmin(UserAdmin):
    model = UserModel
    add_form = AppUserCreationForm
    form = AppUserChangeForm
    list_display = ('pk', 'email', 'is_staff', 'is_superuser')
    search_fields = ('email',)
    ordering = ('pk',)

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ()}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login',)}),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "password1", "password2"),
            },
        ),
    )
```
- **add_form** и **form**: Задават формите за добавяне и редактиране на потребители.

- **list_display**: Определя кои полета ще се виждат в admin панела.

- **search_fields**: Позволява търсене по полета, като например ```email```.

- **fieldsets**: Групира полетата, които ще се показват при редактиране на потребител.

- **add_fieldsets**: Задава полетата, които ще се показват при създаването на нов потребител.

Тази конфигурация позволява на администратора да добавя нови потребители, да редактира съществуващи и да вижда допълнителната информация и права на всеки потребител.

---

## 04.Django Middlewares and Sessions

**1.What is Middleware**

Middleware е начин в Django да обработваме ```заявки (requests)``` и ```отговори (responses)```, преди те да достигнат до view функциите или след като те са изпълнени. Това е подход, който помага на Django да изпълнява различни функции за сигурност, управление на сесии и други. Всеки middleware е като "филтър", който добавя определена функционалност към приложението.

Видове Django Middleware:

- **SecurityMiddleware**: Подобрява сигурността, като гарантира, че сайтът работи само през защитена връзка (HTTPS) и добавя настройки, които предпазват от хакерски атаки.

- **SessionMiddleware**: Управлява сесиите на потребителите.

- **CommonMiddleware**: Управлява кеширане и някои други общи настройки.

- **CsrfViewMiddleware**: Осигурява защита срещу CSRF атаки.

- **AuthenticationMiddleware**: Позволява проверка на автентикация.

Пример за middleware:

```
# Пример за custom middleware
class MyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Код преди view функцията
        print("Това е преди view функцията.")

        response = self.get_response(request)

        # Код след изпълнението на view функцията
        print("Това е след изпълнението на view функцията.")
        return response
```
Този код добавя текст преди и след изпълнението на всяка заявка, което може да е полезно за логване или обработка на данни.

**2. Django Sessions**

Сесиите са начин за запазване на информация за всеки потребител поотделно. Когато потребител се свърже с приложението, може да се създаде сесия, която да запази информация като идентификация на потребителя, предпочитания и други.

Пример за използване на сесии:

```
from django.shortcuts import render

def index(request):
    num_visits = request.session.get('num_visits', 0)  # получаване на броя посещения
    request.session['num_visits'] = num_visits + 1  # увеличаване на броя посещения

    return render(request, 'index.html', {'num_visits': num_visits})
```

Тук използваме ```request.session``` като речник, за да запазим броя посещения на страницата от потребителя.

**Как се активират сесиите?** В ```settings.py``` трябва да добавим ```'django.contrib.sessions'``` към ```INSTALLED_APPS``` и ```'django.contrib.sessions.middleware.SessionMiddleware'``` към ```MIDDLEWARE```.

**3. Cookies**

Cookies са малки файлове, съхранявани на устройството на потребителя и съдържащи информация за посещението му. В Django се използват основно за съхранение на session ID, за да се идентифицира уникално сесията на потребителя.

Пример за използване на cookie:

```
def set_cookie_view(request):
    response = HttpResponse("Cookie set!")
    response.set_cookie('my_cookie', 'cookie_value', max_age=3600)  # съхранява се за 1 час
    return response

def get_cookie_view(request):
    cookie_value = request.COOKIES.get('my_cookie', 'Не е зададена cookie')
    return HttpResponse(f'Cookie value: {cookie_value}')
```

Тук ```set_cookie_view``` създава cookie с име ```my_cookie```, а ```get_cookie_view``` чете тази стойност.

---

