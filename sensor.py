"""Platform for sensor integration."""
from __future__ import annotations
from homeassistant.helpers.entity import Entity

from homeassistant.components.sensor import SensorEntity
from homeassistant.const import (
    ELECTRIC_POTENTIAL_VOLT,
    TEMP_CELSIUS,
    CONTENT_TYPE_TEXT_PLAIN,
)
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
    """Set up the sensor platform."""

    lock3 = LockApi.AirbnkLockBleApi(
        hass, "key1", "key2", "put here your macadress in format AAFFBBCCDDEE"
    )

    async_add_devices(
        [VoltageSensor(lock3), LockState(lock3), Lastadvert(lock3), LockEvents(lock3)]
    )


class SensorBase(Entity):
    """This is the base class for all sensors , and makes easy mqtt subscription to the lock mqtt message broadcasted by Tasmota ESP32 FiRMWARE"""

    should_poll = False

    def __init__(self, lock: LockApi.AirbnkLockBleApi):
        """Initialize the sensor."""
        self._lock = lock
        #REPLACE NEXT SECTION with your tasmota tele message . just replace tasmota_ ... ,to be like tele/your device/BLE
        self._state_topic = "tele/tasmota_DD5424/BLE"

    @property
    def device_info(self):
        """Return information to link this entity with the correct device."""
        return {"identifiers": {(DOMAIN, self._lock.macadress)}}

    # This property is important to let HA know if this entity is online or not.
    # If an entity is offline (return False), the UI will refelect this.
    # @property
    # def available(self) -> bool:
    #   """Return True if roller and hub is available."""
    #  return self._roller.online and self._roller.hub.online

    async def async_added_to_hass(self):
        """Run when this Entity has been added to HA."""
        # Sensors should also register callbacks to HA when their state changes

        self._lock.register_callback(self.async_write_ha_state)

        @callback
        def message_received(topic: str, payload: str, qos: int) -> None:

            self._lock.dealwithmqttmsg(payload)

        await mqtt.async_subscribe(self.hass, self._state_topic, message_received)

    async def async_will_remove_from_hass(self):
        """Entity being removed from hass."""
        # The opposite of async_added_to_hass. Remove any registered call backs here.
        self._lock.remove_callback(self.async_write_ha_state)


class VoltageSensor(SensorBase):
    """Representation of a Sensor."""

    def __init__(self, lock: LockApi.AirbnkLockBleApi):
        """Initialize the sensor."""
        super().__init__(lock)
        self._state = "0"

    @property
    def state(self):
        """Return the state of the sensor."""
        return self._lock.voltage

    @property
    def unique_id(self):
        """Return Unique ID string."""
        return f"{self._lock.macadress}_Voltage"

    @property
    def unit_of_measurement(self) -> str:
        """Return the unit of measurement."""
        return ELECTRIC_POTENTIAL_VOLT

    def update(self) -> None:
        """Fetch new state data for the sensor.

        This is the only method that should fetch new data for Home Assistant.
        """
        self._state = self._lock.lastmqttmsg


class LockState(SensorBase):
    """Representation of a Sensor."""

    def __init__(self, lock: LockApi.AirbnkLockBleApi):
        """Initialize the sensor."""
        super().__init__(lock)
        self._state = self._lock.state

    @property
    def state(self):
        """Return the state of the sensor."""
        return self._lock.state

    @property
    def unique_id(self):
        """Return Unique ID string."""
        return f"{self._lock.macadress}_State"

    def update(self) -> None:
        """Fetch new state data for the sensor.

        This is the only method that should fetch new data for Home Assistant.
        """
        self._state = self._lock.state


class LockEvents(SensorBase):
    """Representation of a Sensor."""

    def __init__(self, lock: LockApi.AirbnkLockBleApi):
        """Initialize the sensor."""
        super().__init__(lock)
        self._state = self._lock.lockEvents

    @property
    def state(self):
        """Return the state of the sensor."""
        return self._lock.lockEvents

    @property
    def unique_id(self):
        """Return Unique ID string."""
        return f"{self._lock.macadress}_Events"

    def update(self) -> None:
        """Fetch new state data for the sensor.

        This is the only method that should fetch new data for Home Assistant.
        """
        self._state = self._lock.lockEvents


class Lastadvert(SensorBase):
    """Representation of a Sensor."""

    def __init__(self, lock: LockApi.AirbnkLockBleApi):
        """Initialize the sensor."""
        super().__init__(lock)
        self._state = self._lock.lastmqttmsg

    @property
    def unique_id(self):
        """Return Unique ID string."""
        return f"{self._lock.macadress}_LastAdv"

    @property
    def state(self):
        """Return the state of the sensor."""
        return self._lock.lastmqttmsg

    def update(self) -> None:
        """Fetch new state data for the sensor.

        This is the only method that should fetch new data for Home Assistant.
        """

        self._state = self._lock.lastmqttmsg
