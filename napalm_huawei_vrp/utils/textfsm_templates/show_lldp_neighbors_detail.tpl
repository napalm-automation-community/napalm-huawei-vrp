Value LOCAL_INTERFACE (.*)
Value REMOTE_CHASSIS_ID (.*)
Value REMOTE_PORT (.*)
Value REMOTE_PORT_DESCRIPTION (.+)
Value REMOTE_SYSTEM_NAME (.*)
Value REMOTE_SYSTEM_DESCRIPTION (.+)
Value REMOTE_SYSTEM_CAPAB (.*)
Value REMOTE_SYSTEM_ENABLE_CAPAB (.*)

Start
  ^Local Intf\s*?[:-]\s+${LOCAL_INTERFACE}
  ^Chassis ID\s*?[:-]\s+${REMOTE_CHASSIS_ID}
  ^Port ID\s*?[:-]\s+${REMOTE_PORT}
  ^Port description\s*?[:-]\s+${REMOTE_PORT_DESCRIPTION}
  ^System name\s*?[:-]\s+${REMOTE_SYSTEM_NAME}
  # We need to change state to capture the entire next line
  ^System description: -> Description
  ^System description\s*-\s*${REMOTE_SYSTEM_DESCRIPTION}
  ^System capabilities supported\s*?[:-]\s+${REMOTE_SYSTEM_CAPAB}
  ^System capabilities enabled\s*?[:-]\s+${REMOTE_SYSTEM_ENABLE_CAPAB} -> Record

Description
  # Capture the entire line and go back to Neighbor state
  ^${REMOTE_SYSTEM_DESCRIPTION} -> Start
