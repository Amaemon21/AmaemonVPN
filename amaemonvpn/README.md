# AmaemonVPN Backend

Node.js + SQLite + YooKassa + AmneziaWG

## Структура

```
amaemonvpn/
├── server.js           # Express сервер
├── db.js               # SQLite схема
├── .env                # Конфиг (создать из .env.example)
├── public/             # Фронтенд (index.html + styles.css сюда)
├── routes/
│   ├── auth.js         # Регистрация, вход
│   ├── payment.js      # СБП оплата + webhook
│   └── user.js         # Профиль, скачать конфиг, QR
├── services/
│   ├── yookassa.js     # YooKassa API
│   └── vpn.js          # Генерация AWG конфигов
└── middleware/
    └── auth.js         # JWT проверка
```

## Установка на сервере

```bash
# 1. Node.js
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs

# 2. Клонировать / закинуть файлы
cd /var/www
mkdir amaemonvpn && cd amaemonvpn
# скопировать все файлы сюда

# 3. Зависимости
npm install

# 4. Конфиг
cp .env.example .env
nano .env  # заполнить все значения

# 5. Фронтенд
mkdir public
cp /path/to/index.html public/
cp /path/to/styles.css public/

# 6. Запустить
node server.js
```

## Переменные окружения (.env)

| Переменная | Описание |
|---|---|
| `JWT_SECRET` | Случайная строка для подписи токенов |
| `YOOKASSA_SHOP_ID` | ID магазина из кабинета ЮКассы |
| `YOOKASSA_SECRET_KEY` | Секретный ключ ЮКассы |
| `VPN_SERVER_IP` | IP твоего сервера |
| `VPN_SERVER_PUBLIC_KEY` | Публичный ключ AWG сервера (`awg show`) |
| `AWG_JC/JMIN/JMAX/S1/S2/H1-H4` | Параметры обфускации из `awg0.conf` |
| `SITE_URL` | URL сайта для редиректа после оплаты |

## Получить публичный ключ AWG сервера

```bash
awg show awg0 | grep 'public key'
```

## Получить параметры обфускации

```bash
cat /etc/amnezia/amneziawg/awg0.conf | grep -E 'Jc|Jmin|Jmax|S1|S2|H[1-4]'
```

## Webhook в ЮКассе

В кабинете ЮКассы → Интеграция → HTTP-уведомления:
```
URL: https://amaemonvpn.ru/api/payment/webhook
Событие: payment.succeeded
```

## API эндпоинты

| Метод | Путь | Описание |
|---|---|---|
| POST | `/api/auth/register` | Регистрация |
| POST | `/api/auth/login` | Вход |
| GET | `/api/user/me` | Профиль + подписка |
| GET | `/api/user/config` | Скачать .conf файл |
| GET | `/api/user/qr` | QR-код PNG |
| POST | `/api/payment/create` | Создать СБП платёж |
| GET | `/api/payment/status` | Статус последнего платежа |
| POST | `/api/payment/webhook` | Webhook от ЮКассы |

## PM2 (автозапуск)

```bash
npm install -g pm2
pm2 start server.js --name amaemonvpn
pm2 save
pm2 startup
```
