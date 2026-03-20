const fs = require('fs')
const path = require('path')
const { homebridge, Accessory, UUIDGen } = require('./types')
const { OutdoorPlugModels, PlugModels, CommonModels, CameraModels, LeakSensorModels,
  TemperatureHumidityModels, LockModels, MotionSensorModels, ContactSensorModels, LightModels,
  LightStripModels, MeshLightModels, ThermostatModels, S1GatewayModels } = require('./enums')

const {
  getValidatedBaseUrls,
  resolveSecrets,
  sanitizeDeviceName,
  wrapLogger
} = require('./security')

const WyzeAPI = require('wyze-api') // Uncomment for Release
//const WyzeAPI = require('./wyze-api/src') // Comment for Release
const WyzePlug = require('./accessories/WyzePlug')
const WyzeLight = require('./accessories/WyzeLight')
const WyzeMeshLight = require('./accessories/WyzeMeshLight')
const WyzeLock = require('./accessories/WyzeLock')
const WyzeContactSensor = require('./accessories/WyzeContactSensor')
const WyzeMotionSensor = require('./accessories/WyzeMotionSensor')
const WyzeTemperatureHumidity = require('./accessories/WyzeTemperatureHumidity')
const WyzeLeakSensor = require('./accessories/WyzeLeakSensor')
const WyzeCamera = require('./accessories/WyzeCamera')
const WyzeSwitch = require('./accessories/WyzeSwitch')
const WyzeHMS = require('./accessories/WyzeHMS')
const WyzeThermostat = require('./accessories/WyzeThermostat')

const PLUGIN_NAME = 'homebridge-wyze-smart-home'
const PLATFORM_NAME = 'WyzeSmartHome'

const DEFAULT_REFRESH_INTERVAL = 30000
const AUTH_FILE_PATTERNS = [
  /^wyze-.*\.json$/i,
  /.*-wyze\.json$/i,
  /^wyze-tokens\.json$/i
]
const AUTH_RECOVERY_COOLDOWN_MS = 60000

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

module.exports = class WyzeSmartHome {
  constructor(log, config, api) {
    this.log = wrapLogger(log)
    this.config = resolveSecrets(config || {}, this.log)
    this.api = api
    this.lastAuthRecoveryAt = 0
    this.client = this.getClient()

    this.accessories = []

    this.api.on('didFinishLaunching', this.didFinishLaunching.bind(this))
  }

  static register() {
    homebridge.registerPlatform(PLUGIN_NAME, PLATFORM_NAME, WyzeSmartHome)
  }

  getPersistPath() {
    return this.config.persistPath || homebridge.user.persistPath()
  }

  getClient() {
    const { authBaseUrl, apiBaseUrl } = getValidatedBaseUrls(this.config, this.log)

    return new WyzeAPI({
      // User login parameters
      username: this.config.username,
      password: this.config.password,
      mfaCode: this.config.mfaCode,
      keyId: this.config.keyId,
      apiKey: this.config.apiKey,
      //Logging
      apiLogEnabled: this.config.apiLogEnabled,
      //App Config
      lowBatteryPercentage: this.config.lowBatteryPercentage,
      //Storage Path
      persistPath: this.getPersistPath(),
      //URLs (strictly validated)
      authBaseUrl,
      apiBaseUrl,
      // App emulation constants
      authApiKey: this.config.authApiKey,
      phoneId: this.config.phoneId,
      appName: this.config.appName,
      appVer: this.config.appVer,
      appVersion: this.config.appVersion,
      userAgent: this.config.userAgent,
      sc: this.config.sc,
      sv: this.config.sv,
      // Crypto Secrets
      fordAppKey: this.config.fordAppKey, // Required for Locks
      fordAppSecret: this.config.fordAppSecret, // Required for Locks
      oliveSigningSecret: this.config.oliveSigningSecret, // Required for the thermostat
      oliveAppId: this.config.oliveAppId, //  Required for the thermostat
      appInfo: this.config.appInfo // Required for the thermostat
    }, this.log)
  }

  shouldRecoverFromAuthError(error) {
    const message = String(error?.message || error || '')

    return message.includes('access token is error') ||
      message.includes('refresh token is error') ||
      message.includes('Refresh Token could not be used to get a new access token')
  }

  clearPersistedAuth() {
    const persistPath = this.getPersistPath()
    let removedCount = 0

    try {
      const stat = fs.statSync(persistPath)

      if (stat.isDirectory()) {
        for (const fileName of fs.readdirSync(persistPath)) {
          if (!AUTH_FILE_PATTERNS.some(pattern => pattern.test(fileName))) continue

          fs.unlinkSync(path.join(persistPath, fileName))
          removedCount += 1
        }
      } else if (stat.isFile()) {
        fs.unlinkSync(persistPath)
        removedCount = 1
      }
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        this.log.warn(`Failed to clear persisted Wyze auth: ${error?.message || error}`)
      }
    }

    return removedCount
  }

  recoverFromAuthError(error) {
    if (!this.shouldRecoverFromAuthError(error)) {
      return false
    }

    const now = Date.now()
    if (now - this.lastAuthRecoveryAt < AUTH_RECOVERY_COOLDOWN_MS) {
      return false
    }

    this.lastAuthRecoveryAt = now
    const removedCount = this.clearPersistedAuth()
    this.client = this.getClient()

    this.log.warn(`Detected invalid Wyze auth tokens. Cleared ${removedCount} persisted auth file(s) from ${this.getPersistPath()} and recreated the Wyze client.`)
    return true
  }

  didFinishLaunching() {
    this.runLoop()
  }

  async runLoop() {
    const baseInterval = this.config.refreshInterval || DEFAULT_REFRESH_INTERVAL
    let failures = 0

    // eslint-disable-next-line no-constant-condition
    while (true) {
      try {
        await this.refreshDevices()
        failures = 0
      } catch (e) {
        failures += 1
        const message = e?.message || String(e)
        this.log.error(`Refresh loop error: ${message}`)
      }

      // simple backoff to avoid noisy retry loops on auth/network failures
      const backoffMultiplier = Math.min(6, failures) // caps at 64x
      const delayMs = baseInterval * (failures === 0 ? 1 : Math.pow(2, backoffMultiplier))
      await delay(delayMs)
    }
  }

  async refreshDevices() {
    if (this.config.pluginLoggingEnabled) this.log('Refreshing devices...')

    try {
      const objectList = await this.client.getObjectList()
      const timestamp = objectList.ts
      const devices = objectList.data.device_list

      if (this.config.pluginLoggingEnabled) this.log(`Found ${devices.length} device(s)`) 
      await this.loadDevices(devices, timestamp)
    } catch (e) {
      if (this.recoverFromAuthError(e)) {
        return this.refreshDevices()
      }

      this.log.error(`Error getting devices: ${e?.message || e}`)
      throw e
    }
  }

  async loadDevices(devices, timestamp) {
    const foundAccessories = []

    for (const device of devices) {
      const accessory = await this.loadDevice(device, timestamp)
      if (accessory) {
        foundAccessories.push(accessory)
      }
    }

    const removedAccessories = this.accessories.filter(a => !foundAccessories.includes(a))
    if (removedAccessories.length > 0) {
      if (this.config.pluginLoggingEnabled) this.log(`Removing ${removedAccessories.length} device(s)`) 
      const removedHomeKitAccessories = removedAccessories.map(a => a.homeKitAccessory)
      this.api.unregisterPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, removedHomeKitAccessories)
    }

    this.accessories = foundAccessories
  }

  async loadDevice(device, timestamp) {
    const safeNickname = sanitizeDeviceName(device.nickname)

    const accessoryClass = this.getAccessoryClass(device.product_type, device.product_model, device.mac, safeNickname)
    if (!accessoryClass) {
      if (this.config.pluginLoggingEnabled) this.log(`[${device.product_type}] Unsupported device type: (Name: ${safeNickname}) (MAC: ${device.mac}) (Model: ${device.product_model})`)
      return
    }
    else if (this.config.filterByMacAddressList?.find(d => d === device.mac) || this.config.filterDeviceTypeList?.find(d => d === device.product_type)) {
      if (this.config.pluginLoggingEnabled) this.log(`[${device.product_type}] Ignoring (${safeNickname}) (MAC: ${device.mac}) because it is in the Ignore Device list`)
      return
    }
    else if (device.product_type == 'S1Gateway' && this.config.hms == false) {
      if (this.config.pluginLoggingEnabled) this.log(`[${device.product_type}] Ignoring (${safeNickname}) (MAC: ${device.mac}) because it is not enabled`)
      return
    }


    let accessory = this.accessories.find(a => a.matches(device))
    if (!accessory) {
      const homeKitAccessory = this.createHomeKitAccessory(device, safeNickname)
      accessory = new accessoryClass(this, homeKitAccessory)
      this.accessories.push(accessory)
    } else {
      if (this.config.pluginLoggingEnabled) this.log(`[${device.product_type}] Loading accessory from cache ${safeNickname} (MAC: ${device.mac})`)
    }
    accessory.update(device, timestamp)

    return accessory
  }

  getAccessoryClass(type, model) {
    switch (type) {
      case 'OutdoorPlug':
        if (Object.values(OutdoorPlugModels).includes(model)) { return WyzePlug }
      case 'Plug':
        if (Object.values(PlugModels).includes(model)) { return WyzePlug }
      case 'Light':
        if (Object.values(LightModels).includes(model)) { return WyzeLight }
      case 'MeshLight':
        if (Object.values(MeshLightModels).includes(model)) { return WyzeMeshLight }
      case 'LightStrip':
        if (Object.values(LightStripModels).includes(model)) { return WyzeMeshLight }
      case 'ContactSensor':
        if (Object.values(ContactSensorModels).includes(model)) { return WyzeContactSensor }
      case 'MotionSensor':
        if (Object.values(MotionSensorModels).includes(model)) { return WyzeMotionSensor }
      case 'Lock':
        if (Object.values(LockModels).includes(model)) { return WyzeLock }
      case 'TemperatureHumidity':
        if (Object.values(TemperatureHumidityModels).includes(model)) { return WyzeTemperatureHumidity }
      case 'LeakSensor':
        if (Object.values(LeakSensorModels).includes(model)) { return WyzeLeakSensor }
      case 'Camera':
        if (Object.values(CameraModels).includes(model)) { return WyzeCamera }
      case 'Common':
        if (Object.values(CommonModels).includes(model)) { return WyzeSwitch }
      case 'S1Gateway':
        if (Object.values(S1GatewayModels).includes(model)) { return WyzeHMS }
      case 'Thermostat':
        if (Object.values(ThermostatModels).includes(model)) { return WyzeThermostat }
    }
  }

  createHomeKitAccessory(device, safeNickname) {
    const uuid = UUIDGen.generate(device.mac)

    const homeKitAccessory = new Accessory(safeNickname, uuid)

    homeKitAccessory.context = {
      mac: device.mac,
      product_type: device.product_type,
      product_model: device.product_model,
      nickname: safeNickname
    }

    this.api.registerPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, [homeKitAccessory])
    return homeKitAccessory
  }

  // Homebridge calls this method on boot to reinitialize previously-discovered devices
  configureAccessory(homeKitAccessory) {
    // Make sure we haven't set up this accessory already
    let accessory = this.accessories.find(a => a.homeKitAccessory === homeKitAccessory)
    if (accessory) {
      return
    }

    const accessoryClass = this.getAccessoryClass(homeKitAccessory.context.product_type, homeKitAccessory.context.product_model)
    if (accessoryClass) {
      accessory = new accessoryClass(this, homeKitAccessory)
      this.accessories.push(accessory)
    } else {
      try {
        this.api.unregisterPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, [homeKitAccessory])
      } catch (error) {
        const safeName = sanitizeDeviceName(homeKitAccessory.context.nickname)
        this.log.error(`Error removing accessory ${safeName} (MAC: ${homeKitAccessory.context.mac}) : ${error?.message || error}`)
      }
    }
  }
}