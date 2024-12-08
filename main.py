import asyncio
import logging
from aiogram import Bot, Dispatcher, types
from aiogram.filters.command import Command
# from aiogram.fsm import FSMContext, State, StatesGroup
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.context import FSMContext
from dotenv import load_dotenv
from api_handler import ApiHandler
import constants, re
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

load_dotenv(override=True)

# Включаем логирование, чтобы не пропустить важные сообщения
logging.basicConfig(level=logging.INFO)
# Объект бота
bot = Bot(token="8061759215:AAEM8PfKVJiE4zCnqpQqqti8PCi1GBdg9Rg")
# Диспетчер
dp = Dispatcher()


class MyStates(StatesGroup):
    started = State()  # Стартовое состояние
    beginning_to_observe = State()  # Состояние ожидания ввода IP или домена
    observing = State()
    finish = State()  # Завершающее состояние

# Хэндлер на команду /start
@dp.message(Command("start"))
async def cmd_start(message: types.Message, state: FSMContext):
    await state.set_state(MyStates.started)
    
    # Список команд
    commands_text = (
        "Добро пожаловать в бота мониторинга уязвимостей! ☺\n\n"
        "Доступные команды:\n"
        "/observe - отправить на проверку домен или IP\n"
        "/getall - все эксплойты и PoC по всем запросам\n\n"
        "Особенности:\n"
        "/getmy - вывести всю историю запросов пользователя\n"
        "После ввода команды выводится список запросов пользователя в виде кнопок. "
        "По нажатию на кнопку вы получите результат по конкретному домену. 😁\n\n"
        "Для начала работы введите команду, например, /observe."
    )
    
    await message.answer(commands_text)

# Хэндлер на команду /observe
@dp.message(Command("observe"))
async def cmd_observe(message: types.Message, state: FSMContext):
    await state.set_state(MyStates.beginning_to_observe)
    await message.answer("Введите домен или ip адрес ресурса, который необходимо мониторить")

# Хэндлер на команду /observe
@dp.message(Command("getall"))
async def cmd_observe(message: types.Message, state: FSMContext):
    await state.set_state(MyStates.beginning_to_observe)
    await message.answer("Список всех эксплойтов и PoC")

    api_handler = ApiHandler()
    vuln_details = api_handler.get_all_vulns()

    # Формируем строку с информацией
    if vuln_details:
        message_response = ""
        for vuln in vuln_details:
            message_response += f"**{vuln['vuln_title']} (ID: {vuln['id']})**\n"
            message_response += f"Request: {vuln['request']}\n"
            message_response += f"Vuln Date: {vuln['vuln_date']}\n"
            message_response += f"Vuln Indicator: {vuln['vulnerability_indicator']}\n"
            message_response += f"Description: {vuln['description'][:300]}...\n"  # Обрезаем описание для удобства
            message_response += f"[More Info]({vuln['description'].split('http')[1]})\n"  # Ссылка на внешний ресурс (если есть)
            message_response += "--------------------------\n"

        await message.answer(message_response)
    else:
        await message.answer("Не удалось найти данные для выбранной уязвимости.")

@dp.message(Command("getmy"))
async def cmd_get_my(message: types.Message, state: FSMContext):
    await state.set_state(MyStates.beginning_to_observe)
    await message.answer("Список всех моих запросов бота")

    api_handler = ApiHandler()
    all_vulns = api_handler.get_my_vulnerabilities()

    # Создаем клавиатуру с кнопками для каждого запроса
    inline_buttons = []

    for vuln in all_vulns:
        # Добавляем кнопку для каждого запроса
        # print("VULN: ", vuln)
        button = InlineKeyboardButton(
            text=f"{vuln['request']}",  # Текст кнопки
            callback_data=f"vuln_{vuln['id']}_{vuln['request']}"  # Передаем id и request
        )
        inline_buttons.append([button])  # Добавляем кнопку как список

    # Создаем клавиатуру
    keyboard = InlineKeyboardMarkup(inline_keyboard=inline_buttons)

    # Отправляем список с кнопками
    await message.answer("Вот список ваших запросов:", reply_markup=keyboard)

MAX_MESSAGE_LENGTH = 4096  # Максимальная длина сообщения в Telegram

def split_message(text, max_length=MAX_MESSAGE_LENGTH):
    # Разбивает текст на части, не превышающие max_length
    parts = []
    while len(text) > max_length:
        split_index = text.rfind('\n', 0, max_length)
        if split_index == -1:  # Если нет переносов строк, разбиваем на max_length символов
            split_index = max_length
        parts.append(text[:split_index])
        text = text[split_index:]
    parts.append(text)  # Добавляем оставшуюся часть текста
    return parts

@dp.callback_query(lambda c: c.data.startswith('vuln_'))
async def handle_vuln_callback(callback_query: types.CallbackQuery):
    # Извлекаем данные из callback_data
    vuln_data = callback_query.data.split('_')
    # print("DATTAAAAA:", vuln_data)
    vuln_id = vuln_data[1]

    # Получаем данные о выбранной уязвимости
    api_handler = ApiHandler()
    vuln_details = api_handler.get_all_vuln_by_id(int(vuln_id))

    if vuln_details:
        message = ""
        for vuln in vuln_details:
            message += f"**{vuln['vuln_title']} (ID: {vuln['id']})**\n"
            message += f"Request: {vuln['request']}\n"
            message += f"Vuln Date: {vuln['vuln_date']}\n"
            message += f"Vuln Indicator: {vuln['vulnerability_indicator']}\n"
            message += f"Description: {vuln['description'][:300]}...\n"
            if 'http' in vuln['description']:  # Проверяем наличие ссылки
                message += f"[More Info](http{vuln['description'].split('http')[1]})\n"
            message += "--------------------------\n"

        # Разбиваем текст на части и отправляем по очереди
        for part in split_message(message):
            await callback_query.message.answer(part, parse_mode="Markdown")
    else:
        await callback_query.message.answer("Не удалось найти данные для выбранной уязвимости.")

    # Подтверждаем, что callback обработан
    await callback_query.answer()


# Метод для обработки домена или IP
@dp.message(MyStates.beginning_to_observe)
async def process_resource(message: types.Message, state: FSMContext):
    # Извлекаем ресурс из состояния
    resource = message.text.strip()

    # Если ресурс не найден в состоянии, просим ввести его снова
    if not resource:
        await message.answer("Ресурс не был передан. Повторите ввод домена или IP.")
        return

    # Пример: Проверка на домен или IP
    api_handler = ApiHandler()

    if re.match(constants.domain_regex, resource):
        resource_type = "домен"
    elif re.match(constants.ipv4_regex, resource):
        resource_type = "IPv4"
    elif re.match(constants.ipv6_regex, resource):
        resource_type = "IPv6"
    else:
        await message.answer(f"Ресурс {resource} некорректный. Укажите правильный домен, IPv4 или IPv6.")
        return

    # Передаем ресурс для сканирования
    result = api_handler.scan_vulns(resource)

    if result == True:
        await message.answer(f"Ваш запрос на мониторинг ресурса ({resource_type}) {resource} находится в обработке.")
    elif result == "Unauthorized":
        await message.answer(f"Неправильные учетные данные бота. Проверьте правильность")
    else:
        await message.answer("Произошла ошибка, повторите попытку позднее")

    # Завершаем процесс
    await state.set_state(MyStates.finish)

# Запуск процесса поллинга новых апдейтов
async def main():
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
