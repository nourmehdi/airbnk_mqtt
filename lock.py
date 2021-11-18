"""Platform for sensor integration."""
from __future__ import annotations
from homeassistant.helpers.entity import Entity
from homeassistant.components.lock import SUPPORT_OPEN, LockEntity
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType
from . import LockApi
from .const import DOMAIN
from homeassistant.components import mqtt


async def async_setup_platform(
    hass: HomeAssistant,
    config: ConfigType,
    async_add_devices,
    discovery_info: DiscoveryInfoType | None = None,
) -> None:
    """Set up the LOCK platform."""

    lock3 = LockApi.AirbnkLockBleApi(
        hass, "key1", "key2", "put here locl mac adrress in format AABBCCDDEE "
    )

    async_add_devices([airbnklock(lock3)])


class airbnklock(LockEntity):
    should_poll = False

    def __init__(self, lock: LockApi.AirbnkLockBleApi) -> None:
        """Initialize the sensor."""
        # Usual setup is done here. Callbacks are added in async_added_to_hass.
        self._lock = lock
        # replace next topic with your tasmota topic
        self._state_topic = "tele/tasmota_DD5424/BLE"  

    async def async_added_to_hass(self) -> None:
        """Run when this Entity has been added to HA."""
        # Importantly for a push integration, the module that will be getting updates
        # needs to notify HA of changes. The dummy device has a registercallback
        # method, so to this we add the 'self.async_write_ha_state' method, to be
        # called where ever there are changes.
        # The call back registration is done once this entity is registered with HA
        # (rather than in the __init__)
        self._lock.register_callback(self.async_write_ha_state)

        @callback
        def message_received(topic: str, payload: str, qos: int) -> None:

            self._lock.dealwithmqttmsg(payload)

        await mqtt.async_subscribe(self.hass, self._state_topic, message_received)

    async def async_will_remove_from_hass(self) -> None:
        """Entity being removed from hass."""
        # The opposite of async_added_to_hass. Remove any registered call backs here.
        self._lock.remove_callback(self.async_write_ha_state)

    @property
    def unique_id(self) -> str:
        """Return Unique ID string."""
        return f"{self._lock.macadress}_Lock"

    @property
    def device_info(self):
        """Return information to link this entity with the correct device."""
        return {"identifiers": {(DOMAIN, self._lock.macadress)}}

    @property
    def is_unlocking(self) -> bool | None:
        return self._lock.isunlocking

    @property
    def is_locking(self) -> bool | None:
        return self._lock.islocking

    @property
    def is_locked(self) -> bool | None:
        return self._lock.islocked

    @property
    def is_jammed(self) -> bool | None:
        return self._lock.isjammed

    @property
    def available(self) -> bool:

        return self._lock.isavailable

    async def async_lock(self, **kwargs):
        """Lock all or specified locks. A code to lock the lock with may optionally be specified."""

        await self._lock.lock()

    async def async_unlock(self, **kwargs) -> None:
        await self._lock.unlock()
