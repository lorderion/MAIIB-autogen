import asyncio

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_agentchat.ui import Console
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_core.models import ModelInfo

from config import Llama_model, Ollama_url, Gemma_model
from tools.nmap_runner import run_nmap
from tools.validators import ScanResult, NmapService

async def main():

    model_client = OpenAIChatCompletionClient(
        model=Llama_model,
        base_url=Ollama_url,
        api_key="ollama",
        model_info=ModelInfo(
            family="Llama3",
            vision=False,
            function_calling=False,
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

    planer_agent = AssistantAgent(
        name="planer_agent",
        model_client=model_client,
        system_message=("Ты планировщик задач. Твоя цель: разбить задачу на шаги"
                        "1) запустить nmap, 2) получить отчет, 3) передать отчет аналитику"
                        "ВАЖНО: для запуска nmap, ты должен передать задачу агенту 'scaner_agent'"
                        "после получения результата от агента 'scaner_agent' ты должен передать всю информацию аналитику 'analyst_agent'.")
    )

    scaner_agent = AssistantAgent(
        name="scaner_agent",
        model_client=Gemma_client,
        tools=[run_nmap],
        system_message=("Ты специалист по сетям, твоя задача просканировать сеть используя инструмент 'run_nmap'"
                        "ОБЯЗАТЕЛЬНЫЙ ПОРЯДОК: если 'planer_agent' говорит тебе, что нужно использовать nmap_scaner, nmap или проанализировать сеть, ты используешь инструмент"
                        "тебе надо сначала дождаться получения результата от инструмента и передать данные обратно к агенту 'planer_agent'")
    )

    analyst_agent = AssistantAgent(
        name="analyst_agent",
        model_client=model_client,
        system_message=("Ты аналитик по кибербезопасности. Твоя цель: получить данные и изучить их."
                        "После изучения данных ты обязан составить отчет чем могут опасны открытые порты."
                        "Поссле отчета ты должен рассказать, как можно обезопаситься.")
    )

    user_query = "localhost"

    ib_team = RoundRobinGroupChat(
        participants=[planer_agent, scaner_agent, analyst_agent],
        max_turns=10
    )

    await Console(ib_team.run_stream(task=f"необходимо проанализировать локальную сеть {user_query}"))

if __name__ == "__main__":
    asyncio.run(main())
