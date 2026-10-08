#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PSN Trophy Scanner & Collector
==============================
Асинхронный скрипт для сбора игроков PlayStation Network (PSN) через официальное API.
Проверяет список аккаунтов (Online ID или Account ID) на наличие выбитых трофеев
в заданной игре с фильтрацией по дате получения, поддержкой ротации прокси,
обработкой 429 (Rate Limit) и потоковым сохранением в TXT.
"""

import asyncio
import argparse
import json
import logging
import os
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple, Any

import aiohttp
from aiohttp_socks import ProxyConnector
from dateutil import parser as date_parser

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("PSNScanner")


# ---------------------------------------------------------------------------
# Config Data Class
# ---------------------------------------------------------------------------
@dataclass
class Config:
    npsso: List[str]
    np_communication_id: str
    trophy_id: Optional[Any] = 0  # int, 'all', or None
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    accounts_file: Optional[str] = None
    proxies_file: Optional[str] = None
    output_file: str = "results.txt"
    output_format: str = "detailed"  # 'detailed', 'simple', 'csv'
    concurrency: int = 3
    request_delay: float = 0.3
    service_name: Optional[str] = None  # 'trophy', 'trophy2', or auto-detect
    resume: bool = True
    account_cache_file: str = "account_cache.json"


# ---------------------------------------------------------------------------
# Proxy Manager
# ---------------------------------------------------------------------------
class ProxyPool:
    """Управление списком прокси с ротацией и обработкой сбоев."""

    def __init__(self, proxy_list: Optional[List[str]] = None):
        self.proxies: List[str] = []
        self.index: int = 0
        self.lock = asyncio.Lock()
        self.failure_counts: Dict[str, int] = {}

        if proxy_list:
            for item in proxy_list:
                normalized = self._normalize_proxy(item)
                if normalized:
                    self.proxies.append(normalized)

        if self.proxies:
            logger.info(f"Загружено {len(self.proxies)} прокси.")
        else:
            logger.info("Прокси не указаны. Работа напрямую через текущий IP.")

    @staticmethod
    def _normalize_proxy(line: str) -> Optional[str]:
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        if "://" in line:
            return line
        # Поддержка формата IP:PORT:USER:PASS или IP:PORT
        parts = line.split(":")
        if len(parts) == 2:
            return f"http://{parts[0]}:{parts[1]}"
        elif len(parts) == 4:
            return f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
        return line

    @classmethod
    def from_file(cls, path: str) -> "ProxyPool":
        if not os.path.exists(path):
            logger.warning(f"Файл с прокси '{path}' не найден!")
            return cls([])
        with open(path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        return cls(lines)

    async def get_proxy(self) -> Optional[str]:
        if not self.proxies:
            return None
        async with self.lock:
            # Выбираем следующий прокси по кругу
            proxy = self.proxies[self.index % len(self.proxies)]
            self.index += 1
            return proxy

    async def report_failure(self, proxy: str):
        async with self.lock:
            cnt = self.failure_counts.get(proxy, 0) + 1
            self.failure_counts[proxy] = cnt
            if cnt >= 5:
                # Если прокси сбоит слишком часто, перемещаем его в конец
                logger.warning(f"Прокси {proxy} сбоит {cnt} раз.")


# ---------------------------------------------------------------------------
# PSN Authentication Manager
# ---------------------------------------------------------------------------
class PSNAuth:
    """
    Авторизация в PSN через npsso токены:
    1. GET /api/authz/v3/oauth/authorize (302 Redirect с code)
    2. POST /api/authz/v3/oauth/token (обмен code на access_token и refresh_token)
    3. Автообновление токена по истечении времени жизни (expires_in).
    Поддерживает ротацию между несколькими NPSSO токенами.
    """

    CLIENT_ID = "09515159-7237-4370-9b40-3806e67c0891"
    REDIRECT_URI = "com.scee.psxandroid.scecompcall://redirect"
    BASIC_AUTH = "Basic MDk1MTUxNTktNzIzNy00MzcwLTliNDAtMzgwNmU2N2MwODkxOnVjUGprYTV0bnRCMktxc1A="
    SCOPE = "psn:mobile.v2.core psn:clientapp"

    def __init__(self, npsso_tokens: List[str], auth_base_url: str = "https://ca.account.sony.com", proxy_pool: Optional[ProxyPool] = None):
        if not npsso_tokens:
            raise ValueError("Не передан ни один NPSSO токен!")
        self.npsso_tokens = [t.strip() for t in npsso_tokens if t.strip()]
        self.auth_base_url = auth_base_url.rstrip("/")
        self.proxy_pool = proxy_pool or ProxyPool([])

        self.token_data: Dict[str, Dict[str, Any]] = {}
        for token in self.npsso_tokens:
            self.token_data[token] = {
                "access_token": None,
                "refresh_token": None,
                "expires_at": 0.0
            }

        self.current_idx = 0
        self.lock = asyncio.Lock()

    def _get_next_npsso(self) -> str:
        token = self.npsso_tokens[self.current_idx % len(self.npsso_tokens)]
        self.current_idx += 1
        return token

    async def _exchange_npsso_for_code(self, npsso: str, session: aiohttp.ClientSession) -> str:
        params = {
            "access_type": "offline",
            "client_id": self.CLIENT_ID,
            "response_type": "code",
            "scope": self.SCOPE,
            "redirect_uri": self.REDIRECT_URI
        }
        url = f"{self.auth_base_url}/api/authz/v3/oauth/authorize?{urllib.parse.urlencode(params)}"
        headers = {
            "Cookie": f"npsso={npsso}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        proxy = await self.proxy_pool.get_proxy()
        async with session.get(url, headers=headers, allow_redirects=False, proxy=proxy if proxy and proxy.startswith("http") else None) as resp:
            # Ожидаем редирект 302/303
            if resp.status in (302, 303):
                location = resp.headers.get("Location")
                if not location:
                    raise RuntimeError(f"Получен статус {resp.status}, но заголовок Location отсутствует.")
                parsed = urllib.parse.urlparse(location)
                qs = urllib.parse.parse_qs(parsed.query)
                code_list = qs.get("code")
                if code_list:
                    return code_list[0]
                raise RuntimeError(f"Код авторизации не найден в Location: {location}")
            elif resp.status == 200:
                body = await resp.text()
                raise RuntimeError(f"Сервер вернул 200 вместо 302 редиректа. Возможно, NPSSO токен устарел или недействителен. Ответ: {body[:200]}")
            else:
                body = await resp.text()
                raise RuntimeError(f"Ошибка запроса authorize: HTTP {resp.status}. Ответ: {body[:200]}")

    async def _exchange_code_for_token(self, code: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        url = f"{self.auth_base_url}/api/authz/v3/oauth/token"
        headers = {
            "Authorization": self.BASIC_AUTH,
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "PlayStation/21090130 CFNetwork/1126 Darwin/19.5.0"
        }
        data = {
            "code": code,
            "redirect_uri": self.REDIRECT_URI,
            "grant_type": "authorization_code",
            "token_format": "jwt"
        }

        proxy = await self.proxy_pool.get_proxy()
        async with session.post(url, headers=headers, data=data, proxy=proxy if proxy and proxy.startswith("http") else None) as resp:
            if resp.status == 200:
                return await resp.json()
            body = await resp.text()
            raise RuntimeError(f"Ошибка обмена кода на токен: HTTP {resp.status}. Ответ: {body[:200]}")

    async def _refresh_access_token(self, refresh_token: str, session: aiohttp.ClientSession) -> Optional[Dict[str, Any]]:
        url = f"{self.auth_base_url}/api/authz/v3/oauth/token"
        headers = {
            "Authorization": self.BASIC_AUTH,
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "PlayStation/21090130 CFNetwork/1126 Darwin/19.5.0"
        }
        data = {
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "token_format": "jwt",
            "scope": self.SCOPE
        }

        proxy = await self.proxy_pool.get_proxy()
        try:
            async with session.post(url, headers=headers, data=data, proxy=proxy if proxy and proxy.startswith("http") else None) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception as e:
            logger.debug(f"Ошибка при попытке refresh токена: {e}")
        return None

    async def get_access_token(self, force_refresh: bool = False) -> str:
        """Получение валидного access_token (с автообновлением при истечении)."""
        async with self.lock:
            npsso = self._get_next_npsso()
            data = self.token_data[npsso]
            now = time.time()

            # Если токен еще жив и не запрошен принудительный сброс
            if not force_refresh and data["access_token"] and data["expires_at"] > now + 60:
                return data["access_token"]

            timeout = aiohttp.ClientTimeout(total=20)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Попробуем обновить через refresh_token, если он есть
                if data["refresh_token"]:
                    refreshed = await self._refresh_access_token(data["refresh_token"], session)
                    if refreshed and "access_token" in refreshed:
                        data["access_token"] = refreshed["access_token"]
                        data["refresh_token"] = refreshed.get("refresh_token", data["refresh_token"])
                        data["expires_at"] = now + int(refreshed.get("expires_in", 3600))
                        logger.info("Access токен успешно обновлен через Refresh токен.")
                        return data["access_token"]

                # Иначе авторизуемся заново по npsso
                logger.info(f"Авторизация в PSN по NPSSO (токен начинается с {npsso[:8]}...)...")
                code = await self._exchange_npsso_for_code(npsso, session)
                token_res = await self._exchange_code_for_token(code, session)

                data["access_token"] = token_res["access_token"]
                data["refresh_token"] = token_res.get("refresh_token")
                data["expires_at"] = now + int(token_res.get("expires_in", 3600))
                logger.info("Access токен успешно получен!")
                return data["access_token"]


# ---------------------------------------------------------------------------
# PSN API Client
# ---------------------------------------------------------------------------
class PSNClient:
    """Клиент для работы с официальными эндпоинтами PSN API."""

    def __init__(
        self,
        auth: PSNAuth,
        api_base_url: str = "https://m.np.playstation.com",
        proxy_pool: Optional[ProxyPool] = None,
        request_delay: float = 0.3,
        account_cache_file: Optional[str] = None
    ):
        self.auth = auth
        self.api_base_url = api_base_url.rstrip("/")
        self.proxy_pool = proxy_pool or ProxyPool([])
        self.request_delay = request_delay
        self.session: Optional[aiohttp.ClientSession] = None
        self.account_cache_file = account_cache_file
        self.account_cache: Dict[str, str] = {}  # online_id (lower) -> account_id
        self._load_cache()

        # Глобальный Rate Limiter & Блокировка на время ожидания 429
        self.rate_limit_lock = asyncio.Lock()
        self.rate_limit_until = 0.0

    def _load_cache(self):
        if self.account_cache_file and os.path.exists(self.account_cache_file):
            try:
                with open(self.account_cache_file, "r", encoding="utf-8") as f:
                    self.account_cache = json.load(f)
                logger.info(f"Загружено {len(self.account_cache)} аккаунтов из кэша.")
            except Exception as e:
                logger.warning(f"Ошибка загрузки кэша аккаунтов: {e}")

    def _save_cache(self):
        if self.account_cache_file:
            try:
                with open(self.account_cache_file, "w", encoding="utf-8") as f:
                    json.dump(self.account_cache, f, ensure_ascii=False, indent=2)
            except Exception as e:
                logger.debug(f"Ошибка сохранения кэша аккаунтов: {e}")

    async def get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=25)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
        self._save_cache()

    async def _handle_rate_limit(self, resp: aiohttp.ClientResponse):
        """Обработка заголовков 429 Rate Limit."""
        now = time.time()
        wait_seconds = 30.0

        # 1. Проверяем Retry-After
        retry_after = resp.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            wait_seconds = float(retry_after)

        # 2. Проверяем X-RateLimit-Next-Available (Unix timestamp в PSN API)
        next_available = resp.headers.get("X-RateLimit-Next-Available")
        if next_available and next_available.isdigit():
            target_ts = float(next_available)
            if target_ts > now:
                wait_seconds = target_ts - now + 2.0

        logger.warning(f"[429 RATE LIMIT] Пауза на {wait_seconds:.1f} сек...")
        self.rate_limit_until = now + wait_seconds
        await asyncio.sleep(wait_seconds)

    async def request(
        self,
        method: str,
        endpoint: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        max_retries: int = 4
    ) -> Tuple[int, Optional[Dict[str, Any]], aiohttp.ClientResponse]:
        """
        Универсальный метод выполнения запросов с обработкой:
        - 429 (Too Many Requests / Rate Limit)
        - 401 (истечение токена и авто-обновление)
        - Сбоев прокси и сети с экспоненциальным backoff.
        """
        session = await self.get_session()
        url = f"{self.api_base_url}/{endpoint.lstrip('/')}" if not endpoint.startswith("http") else endpoint

        if headers is None:
            headers = {}
        headers.setdefault("User-Agent", "PlayStation/21090130 CFNetwork/1126 Darwin/19.5.0")
        headers.setdefault("Accept-Language", "en-US,en;q=0.9")

        for attempt in range(1, max_retries + 1):
            # Проверяем, не находимся ли мы под блокировкой 429
            now = time.time()
            if now < self.rate_limit_until:
                sleep_time = self.rate_limit_until - now
                logger.info(f"Ожидание окончания паузы 429: {sleep_time:.1f} сек...")
                await asyncio.sleep(sleep_time)

            token = await self.auth.get_access_token()
            headers["Authorization"] = f"Bearer {token}"

            proxy = await self.proxy_pool.get_proxy()
            proxy_arg = proxy if proxy and proxy.startswith("http") else None

            try:
                if self.request_delay > 0:
                    await asyncio.sleep(self.request_delay)

                async with session.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    json=json_data,
                    proxy=proxy_arg
                ) as resp:

                    # 1. Обработка 429 Rate Limit
                    if resp.status == 429:
                        async with self.rate_limit_lock:
                            # Проверяем снова, чтобы параллельные корутины не дублировали сон
                            if time.time() >= self.rate_limit_until:
                                await self._handle_rate_limit(resp)
                        continue

                    # 2. Обработка 401 Unauthorized (Токен истек)
                    if resp.status == 401:
                        logger.warning("Получен 401 Unauthorized. Обновление access токена...")
                        await self.auth.get_access_token(force_refresh=True)
                        continue

                    # Чтение тела ответа
                    content_type = resp.headers.get("Content-Type", "")
                    if "application/json" in content_type:
                        try:
                            body_json = await resp.json()
                        except Exception:
                            body_json = None
                    else:
                        body_json = None

                    return resp.status, body_json, resp

            except (aiohttp.ClientError, asyncio.TimeoutError) as err:
                if proxy:
                    await self.proxy_pool.report_failure(proxy)
                backoff = min(2 ** attempt, 15)
                logger.debug(f"[Попытка {attempt}/{max_retries}] Ошибка сети/прокси ({err}). Повтор через {backoff}с...")
                await asyncio.sleep(backoff)

        raise RuntimeError(f"Превышено число попыток ({max_retries}) для запроса {url}")

    async def resolve_account(self, target: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Преобразует Online ID (никнейм) или Account ID в пару (account_id, online_id).
        Если передан уже 19-значный Account ID, поиск не выполняется.
        """
        target = target.strip()
        if not target:
            return None, None

        # Если это уже числовой ID аккаунта (обычно 19 цифр)
        if target.isdigit() and len(target) >= 15:
            return target, target

        # Проверка локального кэша
        target_lower = target.lower()
        if target_lower in self.account_cache:
            return self.account_cache[target_lower], target

        # Поиск через эндпоинт Universal Search
        endpoint = "api/search/v1/universalSearch"
        payload = {
            "searchTerm": target,
            "domainRequests": [
                {"domain": "SocialAllAccounts"}
            ]
        }

        status, data, _ = await self.request("POST", endpoint, json_data=payload)
        if status == 200 and data and "domainResponses" in data:
            for domain_resp in data.get("domainResponses", []):
                for item in domain_resp.get("results", []):
                    meta = item.get("socialMetadata", {})
                    found_online_id = meta.get("onlineId", "")
                    found_acc_id = meta.get("accountId")
                    # Точное совпадение без учета регистра
                    if found_online_id.lower() == target_lower:
                        self.account_cache[target_lower] = str(found_acc_id)
                        return str(found_acc_id), found_online_id

            # Если точного совпадения нет, но есть первый результат
            try:
                first_meta = data["domainResponses"][0]["results"][0]["socialMetadata"]
                found_acc_id = str(first_meta["accountId"])
                found_online_id = first_meta["onlineId"]
                self.account_cache[target_lower] = found_acc_id
                return found_acc_id, found_online_id
            except (KeyError, IndexError):
                pass

        return None, None

    async def get_title_trophies(self, np_communication_id: str, service_name: Optional[str] = None) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
        """
        Получение списка трофеев самой игры (метаданные: названия, типы).
        Автоматически определяет service_name ('trophy' для PS4/PS3/Vita или 'trophy2' для PS5).
        """
        services_to_try = [service_name] if service_name else ["trophy2", "trophy"]
        last_error = ""

        for srv in services_to_try:
            endpoint = f"api/trophy/v1/npCommunicationIds/{np_communication_id}/trophyGroups/all/trophies"
            params = {"npServiceName": srv}
            status, data, _ = await self.request("GET", endpoint, params=params)

            if status == 200 and data and "trophies" in data:
                return srv, data["trophies"], data
            else:
                last_error = f"HTTP {status}"

        raise RuntimeError(f"Не удалось получить список трофеев игры {np_communication_id} ({last_error}). Проверьте npCommunicationId!")

    async def get_user_trophies(
        self,
        account_id: str,
        np_communication_id: str,
        service_name: str
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Получение трофеев конкретного игрока в данной игре.
        Возвращает (STATUS, trophies_list):
          - 'SUCCESS': трофеи успешно получены
          - 'NOT_PLAYED': игра не запущена игроком (404)
          - 'PRIVATE': профиль или трофеи скрыты настройками приватности (403/404)
          - 'NOT_FOUND': аккаунт не найден
          - 'ERROR': иная ошибка
        """
        endpoint = f"api/trophy/v1/users/{account_id}/npCommunicationIds/{np_communication_id}/trophyGroups/all/trophies"
        params = {"npServiceName": service_name}

        status, data, resp = await self.request("GET", endpoint, params=params)

        if status == 200 and data and "trophies" in data:
            return "SUCCESS", data["trophies"]

        if status == 404:
            # Sony возвращает 404 с сообщением "Resource not found" если игрок не запускал игру
            return "NOT_PLAYED", []

        if status == 403:
            # Приватный профиль
            return "PRIVATE", []

        return "ERROR", []


# ---------------------------------------------------------------------------
# Result Writer (Streaming TXT)
# ---------------------------------------------------------------------------
class ResultWriter:
    """Потоковая запись найденных игроков в файл без потери данных при прерывании."""

    def __init__(self, output_path: str, output_format: str = "detailed"):
        self.output_path = output_path
        self.output_format = output_format
        self.lock = asyncio.Lock()
        self.seen_accounts: Set[str] = set()

        # Если файл уже существует, считываем ранее сохраненных игроков
        if os.path.exists(self.output_path):
            with open(self.output_path, "r", encoding="utf-8") as f:
                for line in f:
                    parts = [p.strip() for p in line.split("|")]
                    if parts and parts[0]:
                        self.seen_accounts.add(parts[0].lower())

    async def write_match(
        self,
        online_id: str,
        account_id: str,
        trophy_id: int,
        trophy_name: str,
        trophy_type: str,
        earned_date_iso: str
    ):
        async with self.lock:
            key = online_id.lower()
            if key in self.seen_accounts:
                return
            self.seen_accounts.add(key)

            if self.output_format == "simple":
                line = f"{online_id}\n"
            elif self.output_format == "csv":
                line = f'"{online_id}","{account_id}",{trophy_id},"{trophy_name}","{trophy_type}","{earned_date_iso}"\n'
            else:
                # detailed
                type_str = f"[{trophy_type.upper()}] " if trophy_type else ""
                line = f"{online_id} | {account_id} | Трофей #{trophy_id} {type_str}'{trophy_name}' | Выбит: {earned_date_iso}\n"

            with open(self.output_path, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())


# ---------------------------------------------------------------------------
# Main Scanner Engine
# ---------------------------------------------------------------------------
class PSNScanner:
    """Основной оркестратор асинхронного сканирования."""

    def __init__(self, config: Config, client: Optional[PSNClient] = None):
        self.cfg = config
        self.client = client
        self.writer = ResultWriter(self.cfg.output_file, self.cfg.output_format)

        # Парсинг дат фильтра
        self.dt_from: Optional[datetime] = None
        self.dt_to: Optional[datetime] = None
        if self.cfg.date_from:
            self.dt_from = date_parser.parse(self.cfg.date_from)
            if self.dt_from.tzinfo is None:
                self.dt_from = self.dt_from.replace(tzinfo=timezone.utc)
        if self.cfg.date_to:
            self.dt_to = date_parser.parse(self.cfg.date_to)
            if self.dt_to.tzinfo is None:
                # Если время не указано, берем конец дня
                if "T" not in self.cfg.date_to and " " not in self.cfg.date_to:
                    self.dt_to = self.dt_to.replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
                else:
                    self.dt_to = self.dt_to.replace(tzinfo=timezone.utc)

        # Статистика
        self.stats = {
            "total": 0,
            "processed": 0,
            "matched": 0,
            "not_played": 0,
            "private": 0,
            "not_found": 0,
            "errors": 0
        }
        self.stats_lock = asyncio.Lock()

        # Метаданные трофеев игры
        self.game_trophies: Dict[int, Dict[str, Any]] = {}
        self.service_name: str = "trophy2"

    async def initialize(self):
        """Проверка игры и загрузка названий трофеев."""
        logger.info(f"Получение информации об игре: npCommunicationId={self.cfg.np_communication_id}...")
        service_name, trophies, _ = await self.client.get_title_trophies(
            self.cfg.np_communication_id,
            self.cfg.service_name
        )
        self.service_name = service_name

        for t in trophies:
            tid = t.get("trophyId")
            if tid is not None:
                self.game_trophies[tid] = t

        logger.info(f"Игра определена: сервис {self.service_name.upper()}")
        logger.info(f"Всего трофеев в игре: {len(self.game_trophies)}")

        if self.cfg.trophy_id not in (None, "all", "any"):
            try:
                target_tid = int(self.cfg.trophy_id)
                t_info = self.game_trophies.get(target_tid)
                if t_info:
                    logger.info(f"Целевой трофей: #{target_tid} [{t_info.get('trophyType', '').upper()}] '{t_info.get('trophyName')}'")
                else:
                    logger.warning(f"Трофей с ID #{target_tid} не найден в списке игры! (Будет проверен номер)")
            except ValueError:
                pass

        if self.dt_from or self.dt_to:
            range_str = f"с {self.dt_from or 'любой'} по {self.dt_to or 'любая'}"
            logger.info(f"Фильтр по дате выбивания трофея: {range_str}")

    def _matches_filters(self, trophy_dict: Dict[str, Any]) -> bool:
        """Проверка соответствия выбитого трофея заданным фильтрам."""
        if not trophy_dict.get("earned", False):
            return False

        tid = trophy_dict.get("trophyId")
        # Проверка ID трофея
        if self.cfg.trophy_id not in (None, "all", "any"):
            try:
                if tid != int(self.cfg.trophy_id):
                    return False
            except ValueError:
                return False

        # Проверка даты
        earned_date_str = trophy_dict.get("earnedDateTime")
        if not earned_date_str:
            return False

        try:
            earned_dt = date_parser.isoparse(earned_date_str)
            if earned_dt.tzinfo is None:
                earned_dt = earned_dt.replace(tzinfo=timezone.utc)

            if self.dt_from and earned_dt < self.dt_from:
                return False
            if self.dt_to and earned_dt > self.dt_to:
                return False
        except Exception:
            return False

        return True

    async def _worker(self, queue: asyncio.Queue):
        """Фоновый воркер для обработки очереди аккаунтов."""
        while True:
            try:
                target_acc = await queue.get()
            except asyncio.CancelledError:
                break

            try:
                # 1. Разрешение Online ID -> Account ID
                account_id, online_id = await self.client.resolve_account(target_acc)
                if not account_id:
                    async with self.stats_lock:
                        self.stats["not_found"] += 1
                        self.stats["processed"] += 1
                    logger.debug(f"[{target_acc}] Аккаунт не найден в PSN.")
                    continue

                # 2. Получение списка трофеев пользователя
                status, user_trophies = await self.client.get_user_trophies(
                    account_id,
                    self.cfg.np_communication_id,
                    self.service_name
                )

                if status == "NOT_PLAYED":
                    async with self.stats_lock:
                        self.stats["not_played"] += 1
                        self.stats["processed"] += 1
                elif status == "PRIVATE":
                    async with self.stats_lock:
                        self.stats["private"] += 1
                        self.stats["processed"] += 1
                elif status == "SUCCESS":
                    # Проверяем трофеи игрока
                    matched_any = False
                    for t in user_trophies:
                        if self._matches_filters(t):
                            tid = t.get("trophyId", 0)
                            meta = self.game_trophies.get(tid, {})
                            t_name = meta.get("trophyName", f"Trophy #{tid}")
                            t_type = meta.get("trophyType", t.get("trophyType", ""))
                            earned_date = t.get("earnedDateTime", "")

                            await self.writer.write_match(
                                online_id=online_id or target_acc,
                                account_id=account_id,
                                trophy_id=tid,
                                trophy_name=t_name,
                                trophy_type=t_type,
                                earned_date_iso=earned_date
                            )
                            matched_any = True
                            logger.info(f"[MATCH] {online_id or target_acc} выбил трофей #{tid} ('{t_name}') [{earned_date}]")

                    async with self.stats_lock:
                        if matched_any:
                            self.stats["matched"] += 1
                        self.stats["processed"] += 1
                else:
                    async with self.stats_lock:
                        self.stats["errors"] += 1
                        self.stats["processed"] += 1

                # Логирование текущего прогресса каждые 10 аккаунтов
                if self.stats["processed"] % 10 == 0 or self.stats["processed"] == self.stats["total"]:
                    async with self.stats_lock:
                        logger.info(
                            f"[ПРОГРЕСС {self.stats['processed']}/{self.stats['total']}] "
                            f"Найдено: {self.stats['matched']} | "
                            f"Не играли: {self.stats['not_played']} | "
                            f"Приватные: {self.stats['private']} | "
                            f"Ошибки: {self.stats['errors']}"
                        )

            except Exception as e:
                logger.error(f"Ошибка при обработке {target_acc}: {e}")
                async with self.stats_lock:
                    self.stats["errors"] += 1
                    self.stats["processed"] += 1
            finally:
                queue.task_done()

    async def run(self, accounts: List[str]):
        """Запуск сканирования списка аккаунтов."""
        # Убираем дубликаты
        unique_accounts = list(dict.fromkeys([a.strip() for a in accounts if a.strip()]))

        # Если включен resume, исключаем уже найденных
        if self.cfg.resume and self.writer.seen_accounts:
            before_len = len(unique_accounts)
            unique_accounts = [a for a in unique_accounts if a.lower() not in self.writer.seen_accounts]
            skipped = before_len - len(unique_accounts)
            if skipped > 0:
                logger.info(f"Пропущено {skipped} аккаунтов (уже сохранены в {self.cfg.output_file}).")

        self.stats["total"] = len(unique_accounts)
        logger.info(f"Начало сканирования {self.stats['total']} аккаунтов в {self.cfg.concurrency} потоков...")

        queue = asyncio.Queue()
        for acc in unique_accounts:
            await queue.put(acc)

        # Создаем пул воркеров
        workers = [asyncio.create_task(self._worker(queue)) for _ in range(self.cfg.concurrency)]

        try:
            await queue.join()
        except (asyncio.CancelledError, KeyboardInterrupt):
            logger.warning("Получен сигнал прерывания. Остановка воркеров...")
        finally:
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

        logger.info(
            f"[DONE] Обработано: {self.stats['processed']}/{self.stats['total']} | "
            f"Найдено: {self.stats['matched']} | "
            f"Не играли: {self.stats['not_played']} | "
            f"Приватные: {self.stats['private']} | "
            f"Ошибки: {self.stats['errors']} | "
            f"Файл: {self.cfg.output_file}"
        )


# ---------------------------------------------------------------------------
# CLI & Entry Point
# ---------------------------------------------------------------------------
def parse_arguments() -> Config:
    parser = argparse.ArgumentParser(
        description="PSN Trophy Scanner & Collector — сбор игроков PSN с трофеями по официальному API",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("--config", "-c", type=str, default=None, help="Путь к JSON файлу конфигурации")
    parser.add_argument("--npsso", type=str, default=None, help="NPSSO токен авторизации (64 символа) или список через запятую")
    parser.add_argument("--npsso-file", type=str, default=None, help="Файл со списком NPSSO токенов (по одному на строку)")
    parser.add_argument("--game", "--comm-id", type=str, default=None, help="npCommunicationId игры (например NPWR20188_00)")
    parser.add_argument("--trophy-id", type=str, default="0", help="ID трофея (0 для Платины, или 'all' для любого выбитого трофея)")
    parser.add_argument("--date-from", type=str, default=None, help="Фильтр: дата выбивания трофея ОТ (ГГГГ-ММ-ДД или ISO)")
    parser.add_argument("--date-to", type=str, default=None, help="Фильтр: дата выбивания трофея ДО (ГГГГ-ММ-ДД или ISO)")
    parser.add_argument("--accounts", "-a", type=str, default="accounts.txt", help="Файл со списком никнеймов или ID аккаунтов")
    parser.add_argument("--proxies", "-p", type=str, default=None, help="Файл со списком прокси (http/socks5)")
    parser.add_argument("--output", "-o", type=str, default="results.txt", help="Файл для сохранения найденных игроков")
    parser.add_argument("--format", type=str, choices=["detailed", "simple", "csv"], default="detailed", help="Формат вывода TXT")
    parser.add_argument("--concurrency", type=int, default=3, help="Количество одновременных асинхронных потоков")
    parser.add_argument("--delay", type=float, default=0.3, help="Задержка между запросами (сек) для предотвращения 429")
    parser.add_argument("--service", type=str, choices=["trophy", "trophy2"], default=None, help="Служба: trophy (PS4/PS3) или trophy2 (PS5). По умолчанию авто")
    parser.add_argument("--no-resume", action="store_true", help="Не пропускать ранее сохраненные аккаунты")

    args = parser.parse_args()

    # Загрузка из config.json если указан
    file_cfg = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, "r", encoding="utf-8") as f:
            file_cfg = json.load(f)

    # Сбор NPSSO токенов
    npsso_list: List[str] = []
    if args.npsso:
        npsso_list.extend([t.strip() for t in args.npsso.split(",") if t.strip()])
    elif file_cfg.get("npsso"):
        val = file_cfg["npsso"]
        if isinstance(val, list):
            npsso_list.extend(val)
        else:
            npsso_list.append(str(val))

    npsso_file = args.npsso_file or file_cfg.get("npsso_file")
    if npsso_file and os.path.exists(npsso_file):
        with open(npsso_file, "r", encoding="utf-8") as f:
            npsso_list.extend([l.strip() for l in f if l.strip() and not l.startswith("#")])

    game_id = args.game or file_cfg.get("np_communication_id") or file_cfg.get("game")
    if not game_id:
        print("\n[ERROR] Не указан ID игры! Укажите его через аргумент --game NPWRxxxxx_00 или в config.json\n")
        parser.print_help()
        sys.exit(1)

    if not npsso_list:
        print("\n[ERROR] Не указан NPSSO токен! Получите его в браузере и передайте через --npsso или в config.json\n")
        parser.print_help()
        sys.exit(1)

    return Config(
        npsso=npsso_list,
        np_communication_id=game_id,
        trophy_id=args.trophy_id if args.trophy_id is not None else file_cfg.get("trophy_id", 0),
        date_from=args.date_from or file_cfg.get("date_from"),
        date_to=args.date_to or file_cfg.get("date_to"),
        accounts_file=args.accounts or file_cfg.get("accounts_file", "accounts.txt"),
        proxies_file=args.proxies or file_cfg.get("proxies_file"),
        output_file=args.output or file_cfg.get("output_file", "results.txt"),
        output_format=args.format or file_cfg.get("output_format", "detailed"),
        concurrency=args.concurrency or file_cfg.get("concurrency", 3),
        request_delay=args.delay if args.delay is not None else file_cfg.get("delay", 0.3),
        service_name=args.service or file_cfg.get("service_name"),
        resume=not args.no_resume
    )


async def main():
    cfg = parse_arguments()

    # Загрузка прокси
    proxy_pool = ProxyPool.from_file(cfg.proxies_file) if cfg.proxies_file else ProxyPool([])

    # Инициализация авторизации и клиента
    auth = PSNAuth(cfg.npsso, proxy_pool=proxy_pool)
    client = PSNClient(
        auth=auth,
        proxy_pool=proxy_pool,
        request_delay=cfg.request_delay,
        account_cache_file=cfg.account_cache_file
    )

    # Чтение списка аккаунтов
    if not os.path.exists(cfg.accounts_file):
        logger.error(f"Файл с аккаунтами '{cfg.accounts_file}' не найден!")
        sys.exit(1)

    with open(cfg.accounts_file, "r", encoding="utf-8") as f:
        accounts = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    if not accounts:
        logger.warning(f"Файл '{cfg.accounts_file}' пуст!")
        sys.exit(0)

    scanner = PSNScanner(cfg, client=client)

    try:
        await scanner.initialize()
        await scanner.run(accounts)
    finally:
        await client.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\nСкрипт остановлен пользователем.")
