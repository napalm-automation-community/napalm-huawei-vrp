Value LOCAL_INTERFACE ([^\s]{1,17})

Start
  # Start capturing after the line that start the table
  ^Local Intf -> Record Neighbor

Neighbor
  ^Total entries displayed -> End
  # Stop at the first empty line
  ^$$ -> End
  # Skip 20 characters for the Device ID
  ^.{0}${LOCAL_INTERFACE} -> Record
