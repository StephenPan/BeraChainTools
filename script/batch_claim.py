# -*- coding: utf-8 -*-
# Time     :2024/1/25 03:15
# Author   :ym
# File     :batch_claim.py
import asyncio
import json
import random
from typing import Union

import aiofiles
import aiohttp
from eth_typing import ChecksumAddress, Address
from faker import Faker
from loguru import logger

fake = Faker()


async def get_2captcha_google_token(session: aiohttp.ClientSession) -> Union[bool, str]:
    params = {'key': client_key, 'method': 'userrecaptcha', 'version': 'v3', 'action': 'submit', 'min_score': 0.5,
              'googlekey': '6LfOA04pAAAAAL9ttkwIz40hC63_7IsaU2MgcwVH', 'pageurl': 'https://artio.faucet.berachain.com/',
              'json': 1}
    async with session.get('https://2captcha.com/in.php?', params=params) as response:
        response_json = await response.json()
        # logger.debug(response_json)
        if response_json['status'] != 1:
            logger.warning(response_json)
            return False
        task_id = response_json['request']
    for _ in range(120):
        async with session.get(
                f'https://2captcha.com/res.php?key={client_key}&action=get&id={task_id}&json=1') as response:
            response_json = await response.json()
            if response_json['status'] == 1:
                return response_json['request']
            else:
                await asyncio.sleep(1)
    return False


async def get_2captcha_turnstile_token(session: aiohttp.ClientSession) -> Union[bool, str]:
    params = {'key': client_key, 'method': 'turnstile',
              'sitekey': '0x4AAAAAAARdAuciFArKhVwt',
              'pageurl': 'https://artio.faucet.berachain.com/',
              'json': 1}
    async with session.get('https://2captcha.com/in.php?', params=params) as response:
        response_json = await response.json()
        # logger.debug(response_json)
        if response_json['status'] != 1:
            logger.warning(response_json)
            return False
        task_id = response_json['request']
    for _ in range(120):
        async with session.get(
                f'https://2captcha.com/res.php?key={client_key}&action=get&id={task_id}&json=1') as response:
            response_json = await response.json()
            if response_json['status'] == 1:
                return response_json['request']
            else:
                await asyncio.sleep(1)
    return False


async def get_yescaptcha_google_token(session: aiohttp.ClientSession) -> Union[bool, str]:
    json_data = {"clientKey": client_key,
                 "task": {"websiteURL": "https://artio.faucet.berachain.com/",
                          "websiteKey": "6LfOA04pAAAAAL9ttkwIz40hC63_7IsaU2MgcwVH",
                          "type": "RecaptchaV3TaskProxylessM1S7", "pageAction": "submit"}, "softID": 109}
    async with session.post('https://api.yescaptcha.com/createTask', json=json_data) as response:
        response_json = await response.json()
        if response_json['errorId'] != 0:
            logger.warning(response_json)
            return False
        task_id = response_json['taskId']
    for _ in range(120):
        data = {"clientKey": client_key, "taskId": task_id}
        async with session.post('https://api.yescaptcha.com/getTaskResult', json=data) as response:
            response_json = await response.json()
            if response_json['status'] == 'ready':
                return response_json['solution']['gRecaptchaResponse']
            else:
                await asyncio.sleep(1)
    return False


async def get_yescaptcha_turnstile_token(session: aiohttp.ClientSession) -> Union[bool, str]:
    json_data = {"clientKey": client_key,
                 "task": {"websiteURL": "https://artio.faucet.berachain.com/",
                          "websiteKey": "0x4AAAAAAARdAuciFArKhVwt",
                          "type": "TurnstileTaskProxylessM1"}, "softID": 109}
    async with session.post('https://api.yescaptcha.com/createTask', json=json_data) as response:
        response_json = await response.json()
        if response_json['errorId'] != 0:
            logger.warning(response_json)
            return False
        task_id = response_json['taskId']
    for _ in range(120):
        data = {"clientKey": client_key, "taskId": task_id}
        async with session.post('https://api.yescaptcha.com/getTaskResult', json=data) as response:
            response_json = await response.json()
            if response_json['status'] == 'ready':
                return response_json['solution']['token']
            else:
                await asyncio.sleep(1)
    return False


async def get_ez_captcha_google_token(session: aiohttp.ClientSession) -> Union[bool, str]:
    json_data = {
        "clientKey": client_key, "task": {"websiteURL": "https://artio.faucet.berachain.com/",
                                          "websiteKey": "6LfOA04pAAAAAL9ttkwIz40hC63_7IsaU2MgcwVH",
                                          "type": "ReCaptchaV3TaskProxyless"}, "appId": "34119"}
    async with session.post('https://api.ez-captcha.com/createTask', json=json_data) as response:
        response_json = await response.json()
        if response_json['errorId'] != 0:
            logger.warning(response_json)
            return False
        task_id = response_json['taskId']
    for _ in range(120):
        data = {"clientKey": client_key, "taskId": task_id}
        async with session.post('https://api.ez-captcha.com/getTaskResult', json=data) as response:
            response_json = await response.json()
            if response_json['status'] == 'ready':
                return response_json['solution']['gRecaptchaResponse']
            else:
                await asyncio.sleep(1)
    return False



# 修改的部分：从“ip.txt”文件中读取IP信息
async def get_ip_from_file() -> str:
    ip_list = []
    with open('ip.txt', 'r') as file:
        lines = file.readlines()
        for line in lines:
            ip_list.append(line.strip())

    if not ip_list:
        return ''

    selected_ip = random.choice(ip_list)
    ip_list.remove(selected_ip)

    with open('ip.txt', 'w') as file:
        for ip in ip_list:
            file.write(f"{ip}\n")

    ip_info = selected_ip.split(":")
    if len(ip_info) == 5:
        proxy_string = f'{ip_info[4].lower()}://{ip_info[2]}:{ip_info[3]}@{ip_info[0]}:{ip_info[1]}'
    else:
        proxy_string = f'http://{ip_info[0]}:{ip_info[1]}'

    return proxy_string


# 将成功的地址写入文件
async def write_to_file(address: Union[Address, ChecksumAddress]):
    async with aiofiles.open('claim_success.txt', 'a+') as f:
        await f.write(f'{address}\n')

# 读取文件
async def read_to_file(file_path: str):
    async with aiofiles.open('./claim_success.txt', 'r') as success_file:
        claim_success = await success_file.read()

    async with aiofiles.open(file_path, 'r') as file:
        lines = await file.readlines()
    claim_list = [_address.strip() for _address in lines if _address.strip() not in claim_success]

    return claim_list


# 主要领取水龙头函数
async def claim_faucet(address: Union[Address, ChecksumAddress], google_token: str, session: aiohttp.ClientSession):
    # 请注意，这里的claim_faucet函数覆盖了第一段代码中的原函数，将新的异常处理和写入失败地址的逻辑加入其中。
    user_agent = fake.chrome()
    headers = {'authority': 'artio-80085-ts-faucet-api-2.berachain.com', 'accept': '*/*',
               'accept-language': 'zh-CN,zh;q=0.9', 'authorization': f'Bearer {google_token}',
               'cache-control': 'no-cache', 'content-type': 'text/plain;charset=UTF-8',
               'origin': 'https://artio.faucet.berachain.com', 'pragma': 'no-cache',
               'referer': 'https://artio.faucet.berachain.com/', 'user-agent': user_agent}
    params = {'address': address}
    proxies = await get_ip_from_file()
    try:
        async with session.post('https://artio-80085-faucet-api-cf.berachain.com/api/claim', headers=headers,
                                data=json.dumps(params), params=params, proxy=proxies) as response:
            response_text = await response.text()
        if 'try again' not in response_text and 'message":"' in response_text:
            logger.success(response_text)
            await write_to_file(address)
        elif 'Txhash' in response_text:
            logger.success(response_text)
            await write_to_file(address)
        else:
            logger.warning(response_text.replace('\n', ''))
            await write_failed_address_to_file(address)
    except Exception as e:
        logger.warning(f'Failed to claim faucet for address: {address}, error: {e}')
        await write_failed_address_to_file(address)

# 添加一个新函数用于写入领取失败的地址
async def write_failed_address_to_file(address: Union[Address, ChecksumAddress]):
    async with aiofiles.open('claim_failed.txt', 'a+') as f:
        await f.write(f'{address}\n')

def get_solver_provider():
    provider_dict = {'yescaptcha': get_yescaptcha_turnstile_token, '2captcha': get_2captcha_turnstile_token}
    if solver_provider not in list(provider_dict.keys()):
        raise ValueError("solver_provider must be 'yescaptcha'")
    return provider_dict[solver_provider]


async def claim(address: Union[Address, ChecksumAddress], session: aiohttp.ClientSession):
    try:
        google_token = await get_solver_provider()(session)
        if google_token:
            await claim_faucet(address, google_token, session)
    except Exception as e:
        logger.warning(f'{address}:{e}')


async def run(file_path):
    sem = asyncio.Semaphore(max_concurrent)
    address_list = await read_to_file(file_path)
    async with aiohttp.ClientSession() as session:
        async def claim_wrapper(address):
            async with sem:
                await claim(address, session)

        await asyncio.gather(*[claim_wrapper(address) for address in address_list])


if __name__ == '__main__':
    """
    如果你不能完全的读懂代码，不建议直接运行本程序避免造成损失
    运行时会读取当前文件夹下的claim_success.txt文本，跳过已经成功的地址
    单进程性能会有瓶颈,大概一分钟能领1000左右,自行套多进程或复制多开
    """
    # 验证平台key
    client_key = '68dd9e0622b8c789918be0f79efb02f74569119535458'
    # 目前支持使用yescaptcha 2captcha
    solver_provider = 'yescaptcha'
    # 代理获取链接 设置一次提取一个 返回格式为text
    # get_ip_url = 'http://127.0.0.1:8883/get_ip'
    # 并发数量
    max_concurrent = 4
    # 读取文件的路径 地址一行一个
    _file_path = './address.txt'
    asyncio.run(run(_file_path))

