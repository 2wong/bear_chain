import json
import time
import traceback
from typing import Union, List, Optional, MutableMapping

import cloudscraper
from loguru import logger


def get_yescaptcha_google_token(index: int, scraper: cloudscraper.CloudScraper, proxies: Optional[MutableMapping[str, str]]) -> Union[bool, str]:
    try:
        json_data = {"clientKey": client_key,
                     "task": {
                         "websiteURL": "https://artio.faucet.berachain.com/",
                         "websiteKey": "0x4AAAAAAARdAuciFArKhVwt",
                         "type": "TurnstileTaskProxyless"}}
        response = scraper.post('https://api.yescaptcha.com/createTask', json=json_data, proxies=proxies)
        response_json = response.json()
        if response_json['errorId'] != 0:
            logger.warning(response_json)
            return False
        task_id = response_json['taskId']
        for _ in range(120):
            data = {"clientKey": client_key, "taskId": task_id}
            response = scraper.post('https://api.yescaptcha.com/getTaskResult', json=data, proxies=proxies)
            response_json = response.json()
            if response_json['status'] == 'ready':
                return response_json['solution']['token']
            else:
                time.sleep(1)
        return False
    except Exception as e:
        logger.warning(e)
        return False


def claim_faucet(index: int, addr: str, scraper: cloudscraper.CloudScraper, proxies: Optional[MutableMapping[str, str]]):
    try:
        google_token = get_yescaptcha_google_token(index, scraper, proxies)
        if google_token is False:
            logger.error("get_yescaptcha_google_token error")
            return False
        user_agent = scraper.user_agent.headers['User-Agent']

        headers = {
            'Host': 'artio-80085-faucet-api-cf.berachain.com',
            'sec-ch-ua': '"Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99"',
            'content-type': 'text/plain;charset=UTF-8',
            'sec-ch-ua-mobile': '?0',
            'authorization': f'Bearer {google_token}',
            'user-agent': user_agent,
            'sec-ch-ua-platform': '"Windows"',
            'accept': '*/*',
            'origin': 'https://artio.faucet.berachain.com',
            'sec-fetch-site': 'same-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'referer': 'https://artio.faucet.berachain.com/',
            'accept-language': 'zh-HK,zh-CN;q=0.9,zh;q=0.8',
        }

        params = {'address': addr}
        response = scraper.post('https://artio-80085-faucet-api-cf.berachain.com/api/claim', headers=headers,
                                data=json.dumps(params), params=params, proxies=proxies)
        response_text = response.text
        if 'Added' in response_text and 'queue' in response_text:
            logger.success(f"【{index}】 success claim fauet , {addr}")
            return True
        elif 'rate limit' in response_text:
            logger.warning(f"【{index}】 You have exceeded the rate limit, {addr}")
            return True
        else:
            logger.error(response_text.replace('\n', ''))
    except Exception as e:
        logger.warning(e)
        return False


def claim_with_retry(index, addr, scraper, proxies):
    try:
        if claim_faucet(index, addr, scraper, proxies):
            return True
    except Exception as e:
        logger.error(f"【{index}】  An error occurred: {e}")


def bear_fauet_claim(address: List[str]):
    try:
        if len(address) == 0:
            logger.error('address is None')
            return None

        for index, addr in enumerate(address):
            # 构建 scraper-session 会话
            scraper = cloudscraper.create_scraper(
                    browser={
                        'browser': 'chrome',
                        'platform': 'windows',
                        'mobile': False
                    }
            )
            while True:
                proxies = get_one_proxy()
                if claim_with_retry(index, addr, scraper, proxies):
                    break
                time.sleep(3)
        logger.info('claim ended successfully')
    except Exception as e:
        logger.warning(f'{address}:{e}')


def get_eth_address(filename: str):
    try:
        lines = []
        with open(filename, 'r') as file:
            for line in file:
                lines.append(line)
        return lines
    except Exception:
        logger.error(traceback.format_exc())


def get_one_proxy():
    try:
        proxy_ip, proxy_port, username, password = proxy_url.split(':')
        proxy_string = 'http://' + username + ':' + password + '@' + proxy_ip + ':' + proxy_port
        proxies = {'https': proxy_string, 'http': proxy_string}
        return proxies
    except BaseException:
        traceback.print_exc()


if __name__ == '__main__':
    # 验证平台key,使用yescaptcha
    client_key = ''
    # 动态代理提取地址  域名: 端口:账户: 密码
    proxy_url = ''
    # 读取文件的路径 地址一行一个
    addressList = get_eth_address('address.txt')
    bear_fauet_claim(addressList)
