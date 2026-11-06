import asyncio
from bleak import BleakScanner

async def main():
    # return_adv=True -> dict[address, (BLEDevice, AdvertisementData)]
    found = await BleakScanner.discover(timeout=10.0, return_adv=True)
    print(f"Найдено устройств: {len(found)}")
    for addr, (device, adv) in list(found.items())[:10]:
        print(f"  {device.address}  {device.name}  rssi={adv.rssi}")

asyncio.run(main()