# Django-Advanced
Course at SofUni - October 2024

## Authentication and Autorization


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
**ВИДОВЕ АТАКИ**

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
