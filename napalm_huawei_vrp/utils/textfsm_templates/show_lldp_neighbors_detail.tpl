Value LOCAL_INTERFACE (.*)
Value REMOTE_CHASSIS_ID (.*)
Value REMOTE_PORT (.*)
Value REMOTE_PORT_DESCRIPTION (.+)
Value REMOTE_SYSTEM_NAME (.*)
Value REMOTE_SYSTEM_DESCRIPTION (.+)
Value REMOTE_SYSTEM_CAPAB (.*)
Value REMOTE_SYSTEM_ENABLE_CAPAB (.*)

Start
  ^${LOCAL_INTERFACE}.* has
  ^Chassis ID\s*?[:-]+${REMOTE_CHASSIS_ID}
  ^Port ID\s*?[:-]+${REMOTE_PORT}
  ^Port description\s*?[:-]+${REMOTE_PORT_DESCRIPTION}
  ^System name\s*?[:-]+${REMOTE_SYSTEM_NAME}
  ^System description\s*?[:-]+${REMOTE_SYSTEM_DESCRIPTION}
  ^System capabilities supported\s*?[:-]+${REMOTE_SYSTEM_CAPAB}
  ^System capabilities enabled\s*?[:-]+${REMOTE_SYSTEM_ENABLE_CAPAB} -> Record
