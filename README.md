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

## 05.Django REST Basics

**01. What is API**

**API (Application Programming Interface)** е интерфейс, който позволява на различни софтуерни системи да комуникират помежду си.

**Основни характеристики на API:**

  1. **Посредник**: API действа като посредник между две системи, което означава, че определя как програмите могат да взаимодействат.
  2.  **Методи и протоколи**: Определя правилата (методи, протоколи) за комуникация.
  3.  **Улеснява интеграцията**: Позволява на разработчиците да използват съществуващи функционалности, без да разбират сложните вътрешности на системата.

**Пример за реално приложение:**

Приложение за прогноза за времето. Това приложение използва API, за да вземе данни от сървър за времето:

  - **Клиент**: Приложението за времето изпраща заявка (например град, дата).
  - **Сървър**: API на времето връща информацията (например температура, валежи).

**Видове заявки:**

  - **GET**: Извличане на информация (напр. списък с продукти).

  - **POST**: Създаване на нова информация (напр. добавяне на продукт).

  - **PUT**: Актуализиране на съществуваща информация (напр. редакция на продукт).

  - **DELETE**: Изтриване на съществуваща информация.

Примерна заявка за API (във формат JSON):

```
{
    "endpoint": "/products/",
    "method": "POST",
    "data": {
        "name": "Example Product",
        "price": 19.99
    }
}
```
API прави разработката по-ефективна, като предоставя стандартизирани начини за взаимодействие между различни системи и компоненти.

**2. RESTful APIs**

**RESTful APIs** са интерфейси, базирани на принципите на **REST (Representational State Transfer)**. Те позволяват взаимодействие между различни софтуерни системи чрез стандартни HTTP методи като ```GET```, ```POST```, ```PUT``` и ```DELETE```.

- **Принципи на REST:**

  - **Client-Server Architecture**: Клиентът изпраща заявки, а сървърът връща отговори.
 
  - **Statelessness**: Всяка заявка съдържа цялата информация, необходима за обработката и.
 
  - **Uniform Interface**: Всички взаимодействия следват стандартни правила (URI, HTTP методи).
 
  - **Resource-Based**: Всеки елемент (като книга, потребител) е ресурс с уникален URI.
 
  - **Representation**: Ресурсите се връщат в JSON, XML или други формати.

Пример: API за книги:

  - ```GET /books/``` – връща списък с книги.

  - ```POST /books/``` – добавя нова книга.

  - ```GET /books/1/``` – връща книга с ID = 1.

**3. Django REST Framework (DRF)**

**DRF** улеснява създаването на RESTful API в Django. Някои предимства:

**3.1. Scalability (Скалируемост)**

RESTful APIs са подходящи за приложения, които трябва да се разрастват с увеличаване на броя на потребителите или данните.

  - **Причина**: Архитектурата на REST, базирана на HTTP протокол, позволява хоризонтално скалиране – лесно добавяне на нови сървъри.
  - **Пример:**
    - Големи платформи като Facebook или Amazon използват RESTful APIs, за да управляват милиони заявки от потребители без забавяне.
    - Ако заявките се увеличат, нови сървъри могат да бъдат добавени за обработка на натоварването.
   
**3.2. Simplicity (Простота)**

RESTful APIs са лесни за разбиране, използване и поддръжка.

  - **Причина**: Те използват стандартни HTTP методи ```GET```, ```POST```, ```PUT```, ```DELETE``` и познати формати като JSON или XML.
  - **Пример:**
    - Един разработчик може бързо да разбере как да използва REST API, тъй като документацията често е ясна и следва стандартни правила.
    - За извличане на данни: Просто изпратете ```GET``` заявка до ```/api/products/```.

**3.3. Flexibility (Гъвкавост)**

RESTful APIs поддържат широк набор от клиенти и устройства.

  - **Причина**: Те не са ограничени до конкретна платформа – работят с браузъри, мобилни приложения, IoT устройства и др.
  - **Пример**:
    - Един RESTful API за електронен магазин може да бъде достъпен както от уебсайт, така и от мобилно приложение или смарт устройство (напр. гласов асистент).
   
**3.4. Interoperability (Съвместимост)**

RESTful APIs позволяват взаимодействие между различни системи, платформи и технологии.

- **Причина**: Те използват стандартни протоколи и формати (например HTTP и JSON), които са универсално поддържани.
- **Пример**:
  - API, създадено на Python, може да бъде използвано от приложение на JavaScript или Java, без проблеми с форматирането и комуникацията.
 
**4. Requirements and Installation**

**Изисквания**:

  - Python 3.6+ и Django 3.0+.

**Инсталация**:

```pip install djangorestframework```

Добавете ```rest_framework``` в ```INSTALLED_APPS```:

```
INSTALLED_APPS = [
    ...,
    'rest_framework',
]
```
Добавете URL конфигурация:

```
from django.urls import path, include

urlpatterns = [
    path('api/', include('your_app.urls')),
]
```

**5. Създаване на RESTful API с DRF**

**A. Създаване на модел**

```
from django.db import models

class Book(models.Model):
    title = models.CharField(max_length=100)
    pages = models.IntegerField()
    description = models.TextField()
    author = models.CharField(max_length=50)
```

**B. Сериализатори**

```
from rest_framework import serializers
from .models import Book

class BookSerializer(serializers.ModelSerializer):
    class Meta:
        model = Book
        fields = '__all__'
```

**C. Създаване на APIView**

```
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Book
from .serializers import BookSerializer

class ListBooksView(APIView):
    def get(self, request):
        books = Book.objects.all()
        serializer = BookSerializer(books, many=True)
        return Response({"books": serializer.data})

    def post(self, request):
        serializer = BookSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
```

**D. Добавяне на URL**

```
from django.urls import path
from .views import ListBooksView

urlpatterns = [
    path('books/', ListBooksView.as_view(), name="books-all"),
]
```

**E. Стартиране на сървъра**

```
python manage.py runserver
```

**6. Използване на Postman**

Postman е инструмент за изпращане на HTTP заявки.

  1. **GET заявка**: Изпратете заявка до ```http://127.0.0.1:8000/api/books/```, за да получите списък с книги.
     
  2. **POST заявка**:
   
     -  Въведете URL: ```http://127.0.0.1:8000/api/books/```.
     -  Изберете метод: POST.
     -  Добавете JSON тяло:
    
       ```
       {
         "title": "Example Book",
         "pages": 123,
         "description": "A sample book",
         "author": "John Doe"
      }
      ```

---

## 06. Django REST Advanced

**1. Advanced Serialization**

**Nested serializers** в Django REST Framework (DRF) позволяват да сереализираме и десеализираме сложни вложени структури от данни. Те са полезни в ситуации, когато:

- Съществуват взаимоотношения между модели.
- Необходимо е да включим свързани данни в API отговори или да обработим вложени данни в API заявки.

Пример:

```
from rest_framework import serializers

class BookSerializer(serializers.ModelSerializer):
    class Meta:
        model = Book
        fields = ['title']

class AuthorSerializer(serializers.ModelSerializer):
    books = BookSerializer(many=True, read_only=True)

    class Meta:
        model = Author
        fields = ['name', 'books']
```

В този пример ```AuthorSerializer``` включва информация за свързаните книги на автора, като използва вложен сериалайзер.


Когато имаме модели с взаимоотношения (например Parent и Child), може да използваме вложени сериалайзери, за да обработваме свързани данни при създаване на обект.

Пример:

```
class AuthorSerializer(serializers.ModelSerializer):
    books = BookSerializer(many=True)

    class Meta:
        model = Author
        fields = ['name', 'books']

    def create(self, validated_data):
        books_data = validated_data.pop('books', [])
        author = Author.objects.create(**validated_data)
        for book_data in books_data:
            Book.objects.create(author=author, **book_data)
        return author
```

**2. Generic Views in DRF**

Generic API Views предоставят готови класове за често използвани операции (CRUD). Те опростяват писането на код за общи случаи.

Примери:

  - ```ListAPIView```: Списък с обекти.

  - ```RetrieveAPIView```: Единичен обект по първичен ключ.

  - ```ListCreateAPIView```: Списък + създаване.

Пример за ```ListCreateAPIView```:

```
from rest_framework import generics

class AuthorListCreateView(generics.ListCreateAPIView):
    queryset = Author.objects.all()
    serializer_class = AuthorSerializer
```

**3. Authentication and Permissions in DRF**

**Authentication**

**Автентикацията** проверява идентичността на потребителя. DRF предлага:

  - **Token Authentication**: Използва токени.

  - **Session Authentication**: Базирана на Django сесии.

  - **JWT Authentication**: JSON Web Tokens за сигурност.

Пример за Token Authentication:

```
from rest_framework.authentication import TokenAuthentication
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import authenticate

class LoginView(APIView):
    authentication_classes = [TokenAuthentication]

    def post(self, request):
        user = authenticate(username=request.data['username'], password=request.data['password'])
        if user:
            token, _ = Token.objects.get_or_create(user=user)
            return Response({'token': token.key})
        return Response({'error': 'Invalid credentials'}, status=401)
```

**Permissions**

**Разрешенията** контролират достъпа до ресурси:

  - ```IsAuthenticated```: Разрешава само за автентикирани потребители.

  - ```IsAuthenticated```: Разрешава само за автентикирани потребители.

Пример:

```
from rest_framework.permissions import IsAdminUser

class AdminOnlyView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        return Response({"message": "Welcome, admin!"})
```

**4. Exception Handling in DRF**

Обработката на изключения гарантира предоставянето на смислени съобщения при грешки.
    
Основни изключения:

  - ```APIException```: Базов клас за изключения в DRF.

  - ```Http404```: Обектът не е намерен.

  - ```PermissionDenied```: Потребителят няма достъп.

Пример за персонализирано изключение:

```
from rest_framework.exceptions import APIException

class ServiceUnavailable(APIException):
    status_code = 503
    default_detail = 'Service temporarily unavailable. Try again later.'
    default_code = 'service_unavailable'
```

**Персонализиран обработчик на изключения**

Може да създадете персонализиран обработчик чрез:

```
from rest_framework.views import exception_handler

def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if response is not None:
        response.data['status_code'] = response.status_code
    return response
```

Конфигурация:

```
REST_FRAMEWORK = {
    'EXCEPTION_HANDLER': 'my_project.my_app.utils.custom_exception_handler',
}
```

---

## 07. Asynchronous Оperations

**1. Asynchronous Operations**

Асинхронните операции позволяват изпълнението на задачи без блокиране на основния поток. Това означава, че докато една задача се изпълнява, други могат да се стартират едновременно.

**Пример с Python:**

```
import asyncio

async def do_work():
    print("Working...")
    await asyncio.sleep(1) # Simulates an asynchronous operation that takes 1 second
    print("Work done!")

async def main():
    print("Before asynchronous operation")
    asyncio.create_task(do_work()) # Starts the asynchronous operation concurrently
    print("Doing something else while waiting...")
    await asyncio.sleep(0.5) # Simulates doing something else for 0.5 seconds
    print("Continuing with main operation")
    await asyncio.sleep(0.5) # Simulates more work after the asynchronous operation completes
    print("After asynchronous operation")

asyncio.run(main())
```

**2. Celery**

Celery е библиотека за управление на асинхронни задачи и работи с "workers" (работници), които изпълняват тези задачи.

**Task / Job Queues**

  - Task queues съхраняват задачите, които трябва да се изпълнят. Celery използва брокери на съобщения (например Redis) за управление на тези опашки.

**Scheduling**

Celery позволява планиране на задачи (напр. изпълнение на задача всяка сутрин в 9 часа).

**Пример за дефиниране на задача:**

```
from celery import shared_task

@shared_task
def add(x, y):
    return x + y
```

**Стартиране на работник:**

```
celery -A project_name worker --loglevel=info
```

**3. Redis**

Redis е in-memory база данни, която се използва като брокер на съобщения за Celery. Той осигурява бърз достъп до данни и е идеален за задачи в реално време.

**Redis като Message Broker**

Redis предава съобщения между Celery и работниците. Това е ключово за асинхронната архитектура.

**Настройки за Redis като брокер:**

```
# settings.py
CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
```

**4. Пример: Приложение със Celery и Redis**

**Цел на приложението:**
Създаване на система за генериране на миниатюри (thumbnails) на изображения.

**Ключови стъпки:**

1. **Настройка на проекта:**
   
   - Инсталирайте нужните пакети:
     ```
     pip install celery redis pillow django
     ```
    
2. **Настройка на Celery:**

   - Добавете Celery конфигурация в ```settings.py```.
   - Създайте файл ```celery.py``` за интеграция:
     ```
     from celery import Celery

     app = Celery('project_name', broker='redis://localhost:6379/0')
     app.config_from_object('django.conf:settings', namespace='CELERY')
     app.autodiscover_tasks()
     ```
    
3. **Създаване на задача за генериране на миниатюри:**
   ```
   from PIL import Image
   from celery import shared_task
    
    @shared_task
    def make_thumbnails(file_path, dimensions):
        img = Image.open(file_path)
        for width, height in dimensions:
            img.thumbnail((width, height))
            img.save(f"{file_path}_{width}x{height}.jpg")
    ```
   
4. **Интеграция в Django:**

   - Създайте форма за качване на файлове.
   - Използвайте ```make_thumbnails.delay()``` за асинхронно изпълнение.

5. **Тестване:**

   - Стартирайте Django сървъра.
   - Стартирайте Celery работник:
     ```
     celery -A project_name worker --loglevel=info
     ```

6. **Проверка на статус:**

   ```
   from celery.result import AsyncResult

   result = AsyncResult(task_id)
   print(result.status)
   ```

---


## 08. Unit Testing

**1. Unit и Integration Testing**

**Unit Testing:**

  - **Цел**: Тестване на изолирани модули или функции.
  - **Пример**: Тестване на валидатор в Django.

    ```
    from django.core.exceptions import ValidationError

    def egn_validator(value: str):
        if not value.isdigit():
            raise ValidationError('EGN must contain only digits')
    
    # Unit test
    from unittest import TestCase
    
    class EGNValidatorTestCase(TestCase):
        def test_valid_egn(self):
            try:
                egn_validator("1234567890")
            except ValidationError:
                self.fail("ValidationError raised unexpectedly")
    
        def test_invalid_egn(self):
            with self.assertRaises(ValidationError):
                egn_validator("12345abcd")
    ```

**Integration Testing:**

  - **Цел**: Тестване на взаимодействието между различни компоненти, напр. модели, изгледи, форми.
  - **Пример**: Тестване на регистрация на потребител.

    ```
    from django.test import TestCase, Client
    from django.urls import reverse
    
    class UserRegistrationTestCase(TestCase):
        def setUp(self):
            self.client = Client()
            self.url = reverse('register')
    
        def test_registration_flow(self):
            response = self.client.post(self.url, {
                'username': 'testuser',
                'password1': 'password',
                'password2': 'password',
            })
            self.assertEqual(response.status_code, 302)  # Redirect on success

    ```

**2. Best Practices**

**2.1. Test Granularity**: Разделяй тестовете на малки и независими модули.
**2.2. Triple-A Rule (Arrange, Act, Assert)**:

   - **Arrange**: Настройваш тестовата среда.
   - **Act**: Извикваш кода, който ще тестваш.
   - **Assert**: Проверяваш очакваното поведение.
  
```
def test_sum():
    # Arrange
    a, b = 1, 2
    
    # Act
    result = a + b
    
    # Assert
    assert result == 3
```

**2.3. Single Assertion**: Всяка тестова функция трябва да проверява само един аспект.

**3. Structuring and Organizing Tests**

**3.1. Единични файлове**: tests.py във всяко Django приложение.

**3.2. Папки за тестове**: Създавай tests/ в проектното ниво с поддиректории за различните функционалности.

**Примерна структура:**

```
myproject/
|-- app1/
|   |-- tests/
|       |-- test_models.py
|       |-- test_views.py
|       |-- test_forms.py
|-- app2/
|   |-- tests/
|       |-- test_api.py
```

**4. Testing Django Components**

**Testing Models:**

  - **Пример**: Проверка на custom валидатор.

```
from django.test import TestCase
from myapp.models import Profile

class ProfileModelTestCase(TestCase):
    def test_valid_profile(self):
        profile = Profile(name="Test", age=25, egn="1234567890")
        profile.full_clean()  # Проверка на валидност
        profile.save()
        self.assertIsNotNone(profile.id)
```

**Testing Views:**

  - Тестване на HTTP отговори.

```
class ProfileViewTests(TestCase):
    def test_index_page(self):
        response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'index.html')
```

**5. Live Demo**

Можем да използваме pytest и Django тестовия клиент за изпълнение на тестовете.
Например:

1. **Инсталираме** ```pytest-django:```

   ```
   pip install pytest-django
   ```

2. **Изпълняваме тестовете**:

```
pytest
```

---


## 09. Deployment Setup

1. Gunicorn

   - Не е добра идея да стартираме проекта ни в продъкшън с manage.py поради:
     
     - Автоматично презареждане
     - Грижи се за предоставянето на статични файлове (което е бавно)
     - Single-threaded - Можем да имаме само една инстанция на апликацията
    
  - Gunicorn WSGI (Web Server Gateway Interface)

    - Няма автоматично презареждане (ако изтрием файл на продъкшън няма да рестартираме сървъра.
    - Не предоставя статични файлове.
    - Можем да пуснем няколко инстанции.
    - Грижи се за рестартиране на работниците при проблем, следейки за тяхното изпълнение в един главен процес.
   
  - ```pip install gunicorn```
    
  - ```gunicorn [app_name].wsgi:application --workers=4 bind=0.0.0.0:8000```

1.1 Uvicorn

  - Използва се за стартирне на asgi.
  - Всеки процес е сам за себе си, тоест при евентуално спиране трябва да бъде рестартиран ръчно.
  - Може да бъде комбиниран с gunicorn, за да бъде разрешен този проблем.

2. Reverse Proxy (Nginx)

   - Предоставя статични файлове.
   - Грижи се за SSL.
   - Пренасочва заявките между клиента и django проекта.
   - Serves 80, 443 ports.
   - Nginx е web server, който може да работи като reverse proxy.
   - Настройваме го от nginx.conf.
   - Nginx Пример без и с Docker.
   - Пример с ngrok.

3. Deployment Setup

   - Видове среди
     - Local
     - Development - копие production среда, тоест не е локално, но не е това, което потребителите ползват.
     - Staging - Среда, на която product owner-ите да проверят дали нещата работят
     - Production
    
  - .env файл
    - Файл, в който пазим тайните на проекта ни.
    - os.environ.get('SECRET_KEY', '')
