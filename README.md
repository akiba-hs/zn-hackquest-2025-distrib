# ZeroNights 2025 - HackQuest - Day 6 - N3TW0RK

[English version](#zeronights-2025---hackquest---day-6---n3tw0rk-eng)

----

Контейнер для подключения к 31337 AKIBA n3tw0rk.

Врайтап доступен здесь: [./writeup/](https://github.com/akiba-hs/zn-hackquest-2025-distrib/blob/main/writeup/README.md).

Как играть:
- Стартуй бота [@AkibaNetBot](https://t.me/AkibaNetBot)
- Введи команду `/gen_new_config` - получишь свой ip-адрес и конфиг
- Запускай ~~гуся~~ контейнер:
```sh
docker run --rm -ti --pull=always --privileged ghcr.io/akiba-hs/zn25-net-client -server <server_ip> -auth <your_config>
```
- Попробуй получить флаг =)

> Вместо `--privileged` можно использовать `--cap-add=NET_ADMIN --device=/dev/net/tun`  
> Контейнеру надо только создать виртуальный интерфейс.


## Траблшутинг

Убедись, что используешь последнюю версию контейнера:
```sh
docker pull ghcr.io/akiba-hs/zn25-net-client
```

### Запуск команды выводит `unknown flag: --pull`

Значит у тебя докер старой версии, можешь просто убрать опцию `--pull=always`.  


### Команда для подключения не работает

1. Перепроверь выданный конфиг, и что конфиг всё ещё существует (команда `/list_all` в боте [@AkibaNetBot](https://t.me/AkibaNetBot))

2. Добавь опцию `-debug`, возможно там есть подсказка.


### Контейнер внезапно умер

1. Стартуй контейнер заново, возможно сеть моргнула или сервер перезагрузился.

2. Стартуй контейнер заново с опцией `-debug` и дебажь.


### У меня не ходит трафик в впн

1. Возможно, ты создаёшь много трафика и упираешься в лимиты.

2. Проверь `tail -f /var/log/vpn-client.log`

3. Попробуй перезайти.


### Всё попробовал, ничего не работает

Пиши нам через бота [@AkibaNetBot](https://t.me/AkibaNetBot) (команда `/report`).   
Это читают живые люди (которые ночью могут спать (это не таск на соц инж)).


# ZeroNights 2025 - HackQuest - Day 6 - N3TW0RK (eng)

[Russian version](#zeronights-2025---hackquest---day-6---n3tw0rk)

----

Container to connect to 31337 AKIBA n3tw0rk.

The writeup (in russian) is available here: [./writeup/](https://github.com/akiba-hs/zn-hackquest-2025-distrib/blob/main/writeup/README.md).

To play:
- Start bot [@AkibaNetBot](https://t.me/AkibaNetBot)
- Use `/gen_new_config` command to get your IP and config
- Run the container:
```sh
docker run --rm -ti --pull=always --privileged ghcr.io/akiba-hs/zn25-net-client -server <server_ip> -auth <your_config>
```
- Try to get the flag =)

> Instead of `--privileged` you can use `--cap-add=NET_ADMIN --device=/dev/net/tun`  
> The container needs only to create a TUN interface.


## Troubleshooting

Ensure you use the latest container version:
```sh
docker pull ghcr.io/akiba-hs/zn25-net-client
```

### Running the command outputs `unknown flag: --pull`

This means you have an outdated docker version. You can simply omit the `--pull=always` option.  


### Command for connection doesn't work

1. Check your config and ensure it still exists (`/list_all` command in [@AkibaNetBot](https://t.me/AkibaNetBot))

2. Add `-debug` to the end of `docker run` command--it may give you a clue.


### The container suddenly died

1. Restart the container. There might be network issues or the server had restarted.

2. Restart the container with `-debug` and debug.


### My traffic can't go through VPN

1. This can happen if you generate too much traffic and exceed limits.

2. Check `tail -f /var/log/vpn-client.log`

3. Try to restart the container.


### I've tried everything, nothing works

Reach us via [@AkibaNetBot](https://t.me/AkibaNetBot) (use `/report`).   
Real humans read this (and they can sleep over night (this is not a social engineering task)).

