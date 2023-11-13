# Using the testing framework
To use the testing framework you have to implement two files in addition to the mocked data:

test/unit/test_getters.py - Generic file with the same content as this file test_getters.py
test/unit/conftest.py - Code specific to each driver with instructions on how to fake the driver. For example, conftest.py

# Multiple test cases
To create test cases for your driver you have to create a folder named test/unit/mocked_data/$name_of_test_function/$name_of_test_case. For example:

test/unit/mocked_data/test_get_bgp_neighbors/no_peers/
test/unit/mocked_data/test_get_bgp_neighbors/lots_of_peers/
Each folder will have to contain it’s own mocked data and expected result.

# Command to test TestCase
py.test test/unit/test_getters.py::TestGetter::test_get_bgp_neighbors

pytest -W ignore --no-cov test/unit/test_getters.py::TestGetter::test_get_interfaces