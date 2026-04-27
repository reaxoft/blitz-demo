# Blitz Identity Provider Demo
Сервер аутентификации **Blitz Identity Provider** — это программное обеспечение для управления входом пользователей в приложения. Оно позволяет оснастить веб-сайты и мобильные приложения компании функциями защиты учетных записей пользователей, построенными с учетом лучших современных практик безопасности.

[Документация](https://docs.identityblitz.ru/blitz-idp/#/)

### Для запуска демонстрационной версии необходимо:
1. Установить и запустить [Docker Desktop](https://www.docker.com/products/docker-desktop) (для успешного запуска Blitz IdP потребуется выделить для Docker около 3GB RAM)
2. Склонировать данный репозиторий командой:  
`git clone https://github.com/reaxoft/blitz-demo.git`
3. Перейти в директорию с файлами из репозитория
4. В случае работы на ОС Linux дополнительно необходимо выставить права на файлы командами:
```
chmod -R 777 blitz-config
chmod -R 777 logs
```
5. Запустить Blitz Identity Provider командой:  
`docker-compose up -d`

Для остановки Blitz Identity Provider выполните команду:  
`docker-compose down`

### После запуска будут доступны следующие адреса:
Консоль администрирования:  https://localhost/blitz/console  
Логин/пароль от консоли: admin / blitz-demo

Личный кабинет пользователя: https://localhost/blitz/profile
