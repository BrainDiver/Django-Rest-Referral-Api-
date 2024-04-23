# Referral application DRF
Тестовое задание включает:

- Авторизация через имитацию отправки смс-кодов. Первый запрос на ввод номера телефона и отправку смс-сообщения. Второй запрос ввод кода. Записывает в БД новых пользователей если они еще не были зарегистрированы в ином же случае после второго запроса их авторизует.
- Для каждого пользователя создается инвайт-код, который может быть указан другим пользователем в своем профиле.
- Список номеров телефонов пользователей, которые ввели инвайт-код текущего пользователя включен в его профиль.
- Ecли запрос идет с браузера то приложение работает на Django Templates и в этом случае в первых двух запросах программа лишь выполняет нужные действия но не выводит ответ в JSON формате. В третьем запросе информация выводится в формате Django templates. 
- Если запрос идет с postman или другой программы для отправки запросов то если в GET запросе добавить в headers  Key: application и Value: application в этом случае программа возвращает результаты запросов в JSON формате. 
- Для получения JSON ответа в POST запросе нужно менять headers content-type. Для получения информации как в браузере нужно выставить content-type : application/x-www-form-urlencoded , для получения JSON content-type : application/json


Процесс авторизации завершается авторизацией пользователя и в случае запроса с помощью postman получением токена.<br> **Пройти авторизацию и получить токен можно на html-странице `solution/login` (django-templates), либо через API.**<br><br>
[Коллекция Postman-запросов для тестирования]. Включает скриптованные запросы.<br>
Развернут на [pythonanywhere](https://braindiver.pythonanywhere.com/) (https://braindiver.pythonanywhere.com/).
>На хостинге приложение развернуто с помощью NGINX + uwsgi.

## Auth API
`[GET] solution/login` - Если используется Django templates то будет отображена страница входа где нужно ввести номер телефона. Если в headers добавить Key: application и Value: application то будет выведен json который нужно подать на вход. С post запросами все тоже самое.<br>
⪢ `[POST] solution/login`  - первый запрос на отправку смс-сообщения. Возвращает `sms_token` для предоставления во втором запросе и ссылку на следующий запрос. Зашифрован, содержит в полезной нагрузке отправленный смс-код.
`На вход отдаем номер телефона.`
```json
{
    "phone_number": "+79876543210",
}
```
⪢ `Ответ выглядит подобно этому.`
```json
{
    "sms_token": "2bac0d412823608fcf73081749c13351e5e5236c",
    "url_to_confirm": "http://... ",
}
```
`[GET] solution/sms_verification` - Все так же как и при первом запросе если Django Templates то будет отображена страница где нужно ввести код. Если в headers добавить Key: application и Value: application то будет выведен json который нужно подать на вход. C post запросами все тоже самое <br>
⪢ `[POST] solution/sms_verification` - второй запрос на отправку смс-сообщения. Авторизует пользователя по токену и возвращает этот токен в ответе authorization token. СМС Токен можно ввести в ручную скопировав с ответа в первом запросе. Либо не вводить вовсе и тогда он будет получен с сохраненной сессии. Поскольку отправку кода мы имитируем то код для ввода и отправленный код один "0000". Кроме того в ответ получаем сообщение что мы авторизованы и ссылку на следующий запрос. 
`На вход отдаем sms_token и sms_code`
```json
{
    "sms_token": "",
    "sms_code": "0000"    
}
```
⪢ `Ответ выглядит подобно этому.`
```json
{
    'message': 'Authenticated',
    'auth_token': "2bac0d412823608fcf73081749c13351e5e5246c",
    'profile_url': 'http://...',
}
```
## Profiles API
⪢ `[GET] solution/profile` - Открывается только в том случае если пользователь авторизован приложение посмотрит что за пользователь делает запрос и выдаст его профиль. Если пользователь неавторизован то приложение ответит что такого профиля нет. <br>
`Ответ выглядит подобно этому.`
```json
{
    "phone_number": "+79876543210",
    "referal_code": "d6cdee",
    "referal_user": null or "+798776542101", 
    "invited_users": ["+78324823870", "+79225922366"]
}
```
⪢ `[POST] solution/profile` - ввести реферальный код. Если используется Django Templates то если кода нет то будет отображена форма для ввода если есть то будет выведена вся информация как и при методе get.
`На вход подаем referal_user`
```json
{
    "referal_user": "0fe5d6"
}
```
⪢ `[POST] solution/profile`
`На выходе получаем ответ подобный этому.`
```json
{
    "phone_number": "+79876543210",
    "referal_code": "d6cdee",
    "referal_user": null or "+798776542101", 
    "invited_users": ["+78324823870", "+79225922366"]
}
```