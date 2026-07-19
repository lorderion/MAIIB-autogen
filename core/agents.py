from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_core.models import ModelInfo
from autogen_agentchat.conditions import TextMentionTermination

from config import Llama_model, Ollama_url, Gemma_model
from tools.nmap_runner import run_nmap
from tools.cve_matcher import match_cves

# инициализация клиентов.
model_client = OpenAIChatCompletionClient(
    model=Llama_model,
    base_url=Ollama_url,
    api_key="ollama",
    model_info=ModelInfo(
        family="Llama3",
        vision=False,
        function_calling=True,
        json_output=False,
    ), # type: ignore
    temperature=0.2
)

Gemma_client = OpenAIChatCompletionClient(
    model=Gemma_model,
    base_url=Ollama_url,
    api_key="ollama",
    model_info=ModelInfo(
        family="gemma",
        vision= False,
        function_calling=True,
        json_output=False
    ), # type: ignore
    temperature=0.0,
)
# инициализация агентов.
planner_agent = AssistantAgent(
    name="planer_agent",
    model_client=model_client,
    system_message=("Ты — планировщик (Planner Agent) мультиагентной системы аудита безопасности. "
                "Твоя задача — разбить задачу пользователя на шаги и распределить их между агентами.\n\n"
                "Порядок действий:\n"
                "1. Получи задачу от пользователя.\n"
                "2. Проверь, что цель (target) — это IP или домен. Если нет — запроси уточнение.\n"
                "3. Отправь задачу агенту 'scanner_agent' на запуск сканирования через инструмент 'run_nmap'.\n"
                "4. Дождись результата от 'scanner_agent'. Если ошибка — сообщи пользователю и заверши.\n"
                "5. Передай результат сканирования агенту 'analyst_agent' для анализа уязвимостей и формирования отчёта.\n"
                "6. Получи финальный отчёт от 'analyst_agent' и передай его пользователю.\n\n"
                "Важные правила:\n"
                "- Не выполняй сканирование сам. Только делегируй 'scanner_agent'.\n"
                "- Не анализируй CVE сам. Только передавай данные 'analyst_agent'.\n"
                "- Следи за порядком шагов. Не переходи к шагу N+1, пока не подтверждён шаг N.\n"
                "- При ошибках на любом этапе — явно сообщай об этом и не пытайся «додумать» недостающие данные.\n"
                )
)

scanner_agent = AssistantAgent(
    name="scaner_agent",
    model_client=Gemma_client,
    tools=[run_nmap],
    system_message=("Ты — агент‑сканер (Network Scanner Agent) в мультиагентной системе аудита безопасности. "
                    "Твоя единственная задача — выполнять сканирование сети с помощью инструмента 'run_nmap', "
                    "когда это явно запрашивает агент 'planner_agent'.\n\n"
                    "Правила работы:\n"
                    "1. Никогда не запускай сканирование по собственной инициативе. "
                    "   Запускай инструмент 'run_nmap' только после прямого указания от 'planner_agent'.\n"
                    "2. Формат вызова инструмента: передавай только валидные цели (IP/домен) и список портов. "
                    "   Не пытайся модифицировать аргументы инструмента.\n"
                    "3. После вызова инструмента обязательно дождись результата. "
                    "   В случае ошибки верни понятное сообщение: 'Инструмент вернул ошибку: <описание>' и не продолжай.\n"
                    "4. Результат сканирования (JSON) передай обратно агенту 'planner_agent' как есть, без изменений. "
                    "   Не пытайся интерпретировать или перефразировать технические данные.\n"
                    "5. Безопасность: ты не выполняешь никаких активных атак. "
                    "   Твоя роль — сбор информации (reconnaissance) в рамках согласованного плана.\n\n"
                    "Формат ответа для 'planner_agent':\n"
                    "- Если успех: 'Сканирование завершено. Результат готов для анализа.'\n"
                    "- Если ошибка: 'Ошибка сканирования: <сообщение об ошибке>.'\n"
                    )
)

analyst_agent = AssistantAgent(
    name="analyst_agent",
    model_client=model_client,
    # tools=[match_cves],
    system_message=("Ты — агент‑аналитик по кибербезопасности. Твоя задача — на основе предоставленных данных "
                    "сформировать понятный отчёт для технического руководителя или инженера.\n\n"
                    "Входные данные:\n"
                    "- Список сервисов и портов (из Nmap).\n"
                    "- Найденные CVE (если есть) с описанием и рекомендациями.\n"
                    "- Сводка по уровню риска.\n\n"
                    "Правила:\n"
                    "1. Не пытайся запускать сканирование или искать новые CVE. "
                    "   Используй только те данные, которые тебе передали.\n"
                    "2. В отчёте обязательно укажи:\n"
                    "   - Какие порты и сервисы найдены.\n"
                    "   - Если есть уязвимости: CVE ID, уровень риска, краткое описание.\n"
                    "   - Практические рекомендации (что сделать прямо сейчас).\n"
                    "3. Язык: русский, технический, но понятный не только эксперту.\n"
                    "4. Формат: Markdown. Раздели отчёт на секции: 'Найденные сервисы', 'Уязвимости', 'Рекомендации'.\n"
                    "5. Если уязвимостей не найдено, явно напиши: 'Уязвимостей, соответствующих базе CVE, не обнаружено.'\n\n"
                    "Не выдумывай дополнительные CVE или риски. Если данных недостаточно — запроси уточнения, "
                    "но не продолжай анализ без полной информации."
                    )
)

# инициализация команды агентов.
ib_team = RoundRobinGroupChat(
    participants=[planner_agent, scanner_agent, analyst_agent],
    max_turns=5, termination_condition=TextMentionTermination("done")
)

async def run_team_pipeline(target: str) -> dict:
    """
    Запускает команду в работу.
    """
    try:
        chat_result = await ib_team.run(task=f"Проанализируй сеть: {target}")

        messages = []
        final_report = ""
        done_found = False

        for msg in chat_result.messages:
            entry = {
                "source": msg.source,
                "content": msg.content,
            }
            messages.append(entry)
            if not done_found and "done" in msg.content:
                done_found = True
        if not done_found:
            return {
                "status": "partial",
                "messages": messages,
                "final_report": None,
                "error": "Чат завершился по max_turns, но агент не написал 'DONE'. Возможно, план не был выполнен.",
            }
        for m in reversed(messages):
            if m["source"]  == "analyst_agent":
                final_report = m["content"]
                break

        return {
            "status": "success",
            "messages": messages,
            "final_report": final_report,
            "error": None,
        }
    except Exception as e:
        return {
            "status": "failed",
            "messages": [],
            "final_report": None,
            "error": str(e),
        }
