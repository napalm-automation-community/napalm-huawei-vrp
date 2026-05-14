# -*- coding: utf-8 -*-
"""Inventory parser for Huawei VRP."""

import re
import json
import os

def _load_card_mapping():
    """Load card name mapping from JSON file."""
    mapping_file = os.path.join(os.path.dirname(__file__), 'card_mapping.json')
    try:
        with open(mapping_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

CARD_NAMES = _load_card_mapping()

def parse_inventory(output):
    """
    Parse display elabel output into a list of inventory entries.
    """
    inventory = []
    lines = output.splitlines()
    i = 0
    current_slot = None
    card_position = 0
    current_card_serial = None
    pending_port_header = None

    while i < len(lines):
        line = lines[i].strip()
        if line.startswith('[') and line.endswith(']'):
            header = line[1:-1]
            block_lines = []
            i += 1
            while i < len(lines) and not (lines[i].strip().startswith('[') and lines[i].strip().endswith(']')):
                block_lines.append(lines[i].strip())
                i += 1

            if header.startswith('Slot_'):
                current_slot = int(header.split('_')[1])
                card_position = 0
                current_card_serial = None
                pending_port_header = None

            elif header.startswith('Port_') or header.startswith('StackPort'):
                pending_port_header = header

            elif header == 'Board Properties':
                if pending_port_header:
                    data = _parse_board_properties(block_lines)
                    if data and data.get('model'):
                        if pending_port_header.startswith('Port_'):
                            port_name = pending_port_header[5:]
                            entry = {
                                'slot': current_slot,
                                'port': port_name,
                                'name': 'Transceiver',
                                'description': data.get('description', ''),
                                'serial': data.get('serial', ''),
                                'part_number': data.get('part_number', ''),
                                'model': data.get('model', ''),
                                'manufactured': data.get('manufactured', ''),
                                'vendor': data.get('vendor', ''),
                            }
                            if current_card_serial:
                                entry['card_serial'] = current_card_serial
                            inventory.append(entry)
                        elif pending_port_header.startswith('StackPort'):
                            parts = pending_port_header.split()
                            port_num = parts[1] if len(parts) > 1 else ''
                            entry = {
                                'slot': current_slot,
                                'port': port_num,
                                'name': 'StackPort',
                                'description': data.get('description', ''),
                                'serial': data.get('serial', ''),
                                'part_number': data.get('part_number', ''),
                                'model': data.get('model', ''),
                                'manufactured': data.get('manufactured', ''),
                                'vendor': data.get('vendor', ''),
                            }
                            if current_card_serial:
                                entry['card_serial'] = current_card_serial
                            inventory.append(entry)
                    pending_port_header = None
                else:
                    data = _parse_board_properties(block_lines)
                    if not data:
                        continue
                    desc = data.get('description', '')
                    model = data.get('model', '')
                    if 'Assembling Components' in desc:
                        inventory.append({
                            'slot': current_slot,
                            'name': 'Chassis',
                            'description': desc,
                            'serial': data.get('serial', ''),
                            'part_number': data.get('part_number', ''),
                            'model': model,
                            'manufactured': data.get('manufactured', ''),
                            'vendor': data.get('vendor', ''),
                        })
                    elif 'Power Module' in desc or model.startswith('PAC') or 'Power Supply' in CARD_NAMES.get(model, ''):
                        inventory.append({
                            'slot': current_slot,
                            'name': 'Power Supply',
                            'description': desc,
                            'serial': data.get('serial', ''),
                            'part_number': data.get('part_number', ''),
                            'model': model,
                            'manufactured': data.get('manufactured', ''),
                            'vendor': data.get('vendor', ''),
                        })
                    else:
                        card_position += 1
                        current_card_serial = data.get('serial', '')
                        card_name = CARD_NAMES.get(model, 'Board Properties')
                        inventory.append({
                            'slot': current_slot,
                            'position': card_position,
                            'name': card_name,
                            'description': desc,
                            'serial': current_card_serial,
                            'part_number': data.get('part_number', ''),
                            'model': model,
                            'manufactured': data.get('manufactured', ''),
                            'vendor': data.get('vendor', ''),
                        })
            # Ignore other headers
        else:
            i += 1
    return inventory

def _parse_board_properties(lines):
    """Extract data from Board Properties lines."""
    data = {}
    for line in lines:
        line = line.strip()
        if not line or '=' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.strip()
        value = value.strip()
        # Remove leading $ or / characters
        while key and key[0] in '$/':
            key = key[1:]
        if key == 'BoardType':
            data['model'] = value
        elif key == 'BarCode':
            data['serial'] = value
        elif key == 'Item':
            data['part_number'] = value
        elif key == 'Description':
            data['description'] = value
        elif key == 'Manufactured':
            data['manufactured'] = value
        elif key == 'VendorName':
            data['vendor'] = value
        elif key == 'Model':
            data['model'] = value
    return data
