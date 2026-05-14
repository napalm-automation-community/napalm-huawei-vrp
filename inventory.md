# get_inventory() Method for Huawei VRP Driver

The `get_inventory()` method returns detailed hardware inventory information from a Huawei VRP device, including chassis, transceivers (SFP/SFP+), expansion cards, and power supplies. Data is parsed from the `display elabel` command.

## Output Format

The method returns a list of dictionaries, each describing one hardware component. Fields may vary depending on the component type.

### Common Fields

| Field | Type | Description |
|-------|------|-------------|
| `slot` | int | Slot number (0, 1, ...) |
| `name` | string | Component type: `Chassis`, `Transceiver`, `Power Supply`, `Rear card`, `Board Properties` (if unrecognized) |
| `description` | string | Component description |
| `serial` | string | Serial number |
| `part_number` | string | Part number (Item) |
| `model` | string | Component model |
| `manufactured` | string | Manufacturing date (YYYY-MM-DD) |
| `vendor` | string | Manufacturer name |

### Additional Fields for Ports (Transceivers)

| Field | Type | Description |
|-------|------|-------------|
| `port` | string | Port name (e.g., `25GE0/0/1`) |
| `card_serial` | string | Serial number of the expansion card this port belongs to (if applicable) |

### Additional Fields for Expansion Cards

| Field | Type | Description |
|-------|------|-------------|
| `position` | int | Sequential position of the card within the slot (starting from 1) |

## Example Output

```json
[
  {
    "slot": 0,
    "name": "Chassis",
    "description": "Assembling Components, Switch Model with 48 ports and 4 uplinks",
    "serial": "SN1234567890ABCDEF",
    "part_number": "12345678-001",
    "model": "SwitchModel-X",
    "manufactured": "2023-05-15",
    "vendor": "Huawei"
  },
  {
    "slot": 0,
    "port": "25GE0/0/1",
    "name": "Transceiver",
    "description": "10300Mbps-850nm-LC-33(OM1),82(OM2),300(OM3),400(OM4)",
    "serial": "TRX9876543210",
    "part_number": "87654321-ABC",
    "model": "RTXM228-552",
    "manufactured": "2024-01-20",
    "vendor": "HUAWEI"
  },
  {
    "slot": 0,
    "position": 1,
    "name": "Rear card",
    "description": "Function Module, Interface card with 8 x 10GE SFP+ ports",
    "serial": "CARD9876543210",
    "part_number": "11223344-555",
    "model": "S7X08000",
    "manufactured": "2024-02-10",
    "vendor": "Huawei"
  },
  {
    "slot": 0,
    "name": "Power Supply",
    "description": "Function Module, AC&240VDC PSU, 1000W Power Module",
    "serial": "PSU123456789",
    "part_number": "99887766-000",
    "model": "PAC1000S56-CB",
    "manufactured": "2023-11-02",
    "vendor": "Huawei"
  }
]

Usage Example
python
from napalm import get_network_driver

driver = get_network_driver('huawei_vrp')
device = driver(hostname='192.168.1.1', username='admin', password='password')
device.open()

inventory = device.get_inventory()
for item in inventory:
    port = item.get('port', '')
    print(f"Slot {item['slot']}: {item['name']} - {port}")

device.close()
Notes
The method automatically answers Y to the Continue? [Y/N] prompt when executing display elabel.

A card_mapping.json file is shipped with the driver, which maps card models to human-readable names (e.g., S7X08000 → Rear card). If a model is not found, it defaults to Board Properties. You can extend this file with your own entries.

Empty ports (without transceivers) are omitted from the output.

The vendor field for transceivers is extracted from the /$VendorName line in the display elabel output.

Extending Card Mappings
The card_mapping.json file is located in the napalm_huawei_vrp/ directory. You can add or override mappings:

json
{
  "S7X08000": "Rear card",
  "S7Y08000": "Rear card",
  "ES5D21X08S00": "Rear card",
  "MY_CUSTOM_MODEL": "Custom card"
}