import asyncio
import math
import os
import struct
from bleak.backends.bluezdbus.advertisement_monitor import OrPattern
from bleak.backends.bluezdbus.scanner import BlueZScannerArgs
import httpx
import zlib
from time import monotonic as Now
import anyio
import anyio.abc
from anyio import sleep, create_task_group, run
from loguru import logger
from collections import defaultdict, namedtuple
from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from dotenv import load_dotenv

""""Statistical period:

Every 10>X>999 seconds, the sensor starts a new measuring window. 
After the window it starts advertising the window's enters/exits.
This means we are delayed by window amount of seconds, by default 60, minimum 10, 1 second steps.

Message counter byte is increment by one every time a new window starts.
"""


class keydefaultdict(defaultdict):

    def __missing__(self, key):
        if self.default_factory is None:
            raise KeyError(key)
        else:
            ret = self[key] = self.default_factory(key)
            return ret


HumanMonitorPayload = namedtuple(
    "HumanMonitorPayload",
    "type subtype subsubtype msgcounter enters exits undefined seed checksum",
)

load_dotenv()
CALLBACK_URL = "https://dfapi.tt.utu.fi/minew"
BEARER_TOKEN = os.getenv("BEARER_TOKEN")
posting_payload = defaultdict(lambda: False)
SUBMIT_CHECK_INTERVAL = int(os.getenv("SUBMIT_CHECK_INTERVAL", "9")) 


def same_payload(a: HumanMonitorPayload, b: HumanMonitorPayload):
    if a.enters == b.enters and a.exits == b.exits:
        return True
    return False


async def send_payload_task(deviceIdentifier):
    parsed = devices[deviceIdentifier]
    if posting_payload[deviceIdentifier]:
        return
    try:
        posting_payload[deviceIdentifier] = True
        payload = {
            "device": deviceIdentifier,
            "deviceIdOrHash":
            zlib.crc32(bytes.fromhex(deviceIdentifier)) % 127,
            "exits": parsed.exits,
            "enters": parsed.enters,
            "msgcounter": parsed.msgcounter,
        }
        async with httpx.AsyncClient() as client:
            await client.post(CALLBACK_URL, json=payload, timeout=3,headers={
                "User-Agent": "Minew Connect V3 Human Flow Monitor",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {BEARER_TOKEN}" if BEARER_TOKEN else None
            })
        print(payload)
    finally:
        posting_payload[deviceIdentifier] = False
    return


# MineW @ https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/company_identifiers/company_identifiers.yaml
MINEW_LE = 0x0639
MINEW_LE_BYTES = b"\x39\x06"
devices = keydefaultdict(lambda x: DeviceState(x))


class DeviceState():
    total_enter = -1
    total_exit = -1

    # Submission
    CALLBACK_URL = CALLBACK_URL
    total_enter_submitted = -1
    total_exit_submitted = -1

    # ID
    deviceIdentifier: str = ""
    deviceid: int = -1

    # Tracking
    payload_prev = None
    prev_msgnum = None

    def __init__(self, deviceIdentifier):
        self.deviceIdentifier = deviceIdentifier
        self.deviceid = int(self.deviceIdentifier, 16) % 127
        self.payload_prev = None
        self.prev_msgnum = None
        self.total_enter = 0
        self.total_exit = 0
        self.submit_check_task = asyncio.create_task(self.submit_check_loop())

    async def submit_check_loop(self):
        while True:
            await sleep(SUBMIT_CHECK_INTERVAL)
            if not self.payload_prev:
                logger.debug(
                    f"Device {self.deviceIdentifier} has no payload yet, skipping submit check"
                )
                continue
            try:
                if not (await self.submit_check()):
                    continue
                logger.info(
                    f"Submitting {self.total_enter} enters and {self.total_exit} exits for device {self.deviceid}"
                )
                await self.send_payload_task()
            except Exception as e:
                logger.exception(
                    f"Error submitting payload for device {self.deviceid}: {e}"
                )
    async def send_payload_task(self):
        deviceid = self.deviceid
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(
                    self.CALLBACK_URL,
                    json={
                        "deviceid": deviceid % 127,
                        "total_exits": self.total_exit,
                        "total_enters": self.total_enter,
                    },
                    timeout=3,
                )
                resp.raise_for_status()
            except httpx.HTTPStatusError as e:
                logger.error(
                    f"Failed to send data for device {self.deviceid}: {e}: {resp.text}"
                )
            except httpx.RequestError as e:
                logger.error(
                    f"Request error while sending data for device {self.deviceid}: {e}"
                )
    def __repr__(self):
        return f"DeviceState({self.deviceIdentifier!r}, total_enter={self.total_enter}, total_exit={self.total_exit})"

    def __str__(self):
        return f"DeviceState({self.deviceIdentifier}, total_enter={self.total_enter}, total_exit={self.total_exit})"

    def on_msgnum(self, msgnum):
        prev = self.prev_msgnum
        self.prev_msgnum = msgnum
        if prev is None:
            logger.info(
                f"Device {self.deviceIdentifier}: First msgnum {msgnum} received"
            )
            return
        if msgnum < prev:
            logger.info(
                f"Device {self.deviceIdentifier}: New msgnum {msgnum} wrapped around"
            )
            prev = prev - 255
        if msgnum - prev > 1:
            logger.warning(
                f"Device {self.deviceIdentifier}: Msgnum {msgnum} is {msgnum-prev} higher than previous {prev}, missed messages?"
            )

    async def submit_check(self):
        if self.total_enter_submitted == self.total_enter and self.total_exit_submitted == self.total_exit:
            return
        self.total_enter_submitted = self.total_enter
        self.total_exit_submitted = self.total_exit
        return True


async def proc(bd: BLEDevice, ad: AdvertisementData,
               tg: anyio.abc.TaskGroup) -> None:
    # print(
    #    f" {bd.name!r} distance={math.pow(10.0,(float(ad.rssi)/(10.0*2.0))) :.3f}m to {math.pow(10.0,(float(ad.rssi)/(10.0*4.0))) :.3f}m with {ad!r}"
    # )
    data = ad.manufacturer_data.get(MINEW_LE, None)
    if not data:
        return  # ???
    if data[0] != 0xCA:
        print("??")
        return  # Not Minew Connect V3
    if data[1] != 0x18:
        return  # Not Radar monitoring frame
    if data[2] != 0x00:
        return  # Not human flow monitoring data frame
    try:
        parsed = HumanMonitorPayload._make(
            struct.unpack("B B B B H H 12s H H", data))
    except struct.error as e:
        logger.error(f"Error unpacking data: {e}")
        return
    # print(parsed.exits, parsed.enters, parsed.msgcounter)
    deviceIdentifier = bd.address.lstrip("C3:00:00:").replace(":", "").lower()
    device = devices[deviceIdentifier]
    device.on_msgnum(parsed.msgcounter)
    prev = device.payload_prev
    if prev and parsed.msgcounter == prev.msgcounter:
        if parsed.enters != prev.enters or parsed.exits != prev.exits:
            logger.warning(
                f"Message counter {parsed.msgcounter} is same as previous but enters/exits differ! {parsed.enters} vs {prev.enters}, {parsed.exits} vs {prev.exits}"
            )
        return

    device.payload_prev = parsed
    device.total_enter += parsed.enters
    device.total_exit += parsed.exits
    logger.info(
        f"payload parsed: enters={parsed.enters} exit={parsed.exits} msgc={parsed.msgcounter} id={deviceIdentifier} TOTAL(ENTER={device.total_enter} EXIT={device.total_exit})",
        enters=parsed.enters,
        exits=parsed.exits,
        msgcounter=parsed.msgcounter,
        deviceIdentifier=deviceIdentifier)

    # tg.start_soon(
    #    send_payload_task,deviceIdentifier
    # )


async def main() -> None:
    async with create_task_group() as tg:
        # OrPattern: https://github.com/hbldh/bleak/discussions/1612#discussioncomment-10045026
        async with BleakScanner(
                scanning_mode="passive",
                bluez=BlueZScannerArgs(
                    or_patterns=[OrPattern(0, 0xFF, MINEW_LE_BYTES)]),
        ) as scanner:
            async for bd, ad in scanner.advertisement_data():
                #               print(bd)
                if bd.address.startswith("C3:00:00"):
                    await proc(bd, ad, tg)


if False:
    a = DeviceState("test")
    a.on_msgnum(254)
    a.on_msgnum(255)
    a.on_msgnum(0)
    a.on_msgnum(1)
    a.on_msgnum(3)

if __name__ == "__main__":
    # asyncio.run(main())
    run(main)
