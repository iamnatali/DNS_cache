## Кэширующий DNS-сервер
студент: Первушина Наталия КН-203

##### Функции и порядок работы
* сервер запускается на localhost ip:127.0.0.1 и слушает 53 порт
* сервер умеет разрешать запросы и отправлять полученный ответ, 
при этом сохраняя в кэш полученный ответ и ответ на дополнительный запрос ANY
* в случае если ANCOUNT = 0, а в ns образуется петля(тот же адрес, 
на который уже посылали), сервер вернет текущий ответ, который может быть не тем,
 чего хотел пользователь, и не запишет его в кэш
* могут быть проблемы с пользовательским запросом ANY
* сервер чистит кэш по ttl при каждом новом запрсе
* кэш - это словарь records_dict, и там хранятся только ответы без прикрепленных записей
* сервер также обрабатывает RCODE(response code) и прервет разрешение, если RCODE не равен
 0000, и выведет значение текущего RCODE  
* при окончании работы сервера с помощью сочетания Ctrl+C данные, хранящиеся в 
records_dict сериализуются с помощью pickle
* при разрешении запроса dns-сервер выводит лог

Пример лога одного сеанса работы dns:

* got data
* start processing
* no answer in cache
* send query to a.root-servers.net
* receive data from a.root-servers.net
* start analysis
* send query to a.dns.ripn.net
* receive data from a.dns.ripn.net
* start analysis
* send query to ns2.yandex.RU
* receive data from ns2.yandex.RU
* start analysis
* found answer
* got once data (это ответ на запрос ANY)
* data to cache
* send answer
* 91 bytes sent
#
* got data
* start processing
* answer from cache
* send answer
* 127 bytes sent
* you exited dns with Ctrl+C
#
* try serializing data
* serialized successfully

##### Справка по использованию
* чтобы начать работу dns-сервера, необходимо запустить dns_main.py
* заканчивается работа сервера сочетание клавиш Ctrl+C(желательно 
завершать ее после того как сервер обработал все запросы 
и написал сколько байт было отправлено, может потребоваться 2 нажатия)
 
