# napalm-skeleton

Congratulations! You are going to embark on an epic adventure that will bring you glory, fame and
fortune.

> “Don't wish, Miss Tick had said. Do things.”
> -- Terry Pratchett

## Instructions

### Before starting

1. Pick a name. Something that can easily identify which NOS you are supporting. From now on we will
call it `SKELETON` so everytime you see `SKELETON` on this repo, replace it with the name you just
picked.
1. Let the `napalm` community know that you are planning to write a new driver. You can try reaching
out on slack or on the mailing list. Someone will create a repo for you under the
[`napalm-automation-community`](https://github.com/napalm-automation-community) organization. You
can host your own driver if you prefer but we think it's more interesting if we can host all of the
drivers together.
You can find more details regarding the [Community drivers guidelines](http://napalm.readthedocs.io/en/develop/contributing/drivers.html).
1. Feel free to amend the Copyright holder.

### Replacing the skeleton to the new repo

`[INSTRUCTIONS TO CLONE THIS REPO AND MOVE CONTENT TO NEW ONE HERE]`

### Fixing the `README.md` and `AUTHORS`

1. Replace the occurrences on this file of `SKELETON`. Replace only the ones above
the `CUTTING_LINE`. Don't bother about `pypi`, `travis`, etc. That will be taking care of later,
after the first merge.
1. Feel free to replace the content of AUTHORS as well and put yourself there. That's what will
bring you the fame and fortune after all ;)
1. Add any other useful information on the `README.md` file you think it's interesting.

### The Driver

All the code should be inside `napalm_skeleton`. You are free to organize your code as you want,
however, there are some parts that have to be done in a certain way:

* `napalm_skeleton/__init__.py` - That file should import your class driver. That's what the
dynamic importer will expect.
* `napalm_skeleton/skeleton.py` - Here goes your driver.
* `napalm_skeleton/templates/` - We use this folder to store templates used by the `load_template`
method.
* `napalm_skeleton/utils/` - For consistency with other repos we recommend putting your additional
code here. Helper functions or anything you want to keep out of the main driver file.
* `napalm_skeleton/utils/textfsm_templates` - For consistency as well, we recommend keeping your
`textfsm` templates here. We are planning to do some stuff around here so might have some common
code that will assume they are there.
* `MANIFEST.in` - If you need some additional support files that are not code, don't forget to add
them to this file. Please, don't forget to set the correct paths.

### The Tests

Code for testing is inside the `test` folder.

* `test/unit/TestDriver.py` - Here goes the following classes:
  * `TestConfigDriver` - Tests for configuration management related methods.
  * `TestGetterDriver` - Tests for getters.
  * `FakeDevice` - Test double for your device.
* `test/unit/skeleton/` - Here goes some configuration files that are used by `TestConfigDriver`.
* `test/unit/skeleton/mock_data/` - Here goes files that contain mocked data used by
                                    `TestGetterDriver`.

#### Testing configuration management methods

This is tricky. Cloud CI services like `Travis-CI` don't support running virtual machines and
we currently don't have the resources or the means to test from a cloud service or with real
machines. Moreover, mocking this might be very difficult and error prone. Vendors like changing
the internal with every minor release and we might have end up mocking several parts of the system
that are undocumented and have hundreds of edge cases. The only way we could safely mock this is
if vendors would provide us with their parsers and that's not going to happen. Because of these
reasons, the only safe way of testing is by using a VM or physical machine and testing manually
every time someone pushes code that changes a configuration management method. Luckily, these are
limited so once they are stable we can forget about them.

If there is a VM available, please, provide a vagrant environment and use it for the tests,
that way other developers will be able to test as well.

If you want Travis CI for your new driver (once hosted under the
[`napalm-automation-community`](https://github.com/napalm-automation-community)
organization), just let us know and we'll enable it for you.

#### Testing getters

This is easier, we can use a real machine or just mock the device. Write a test double for your
device and provide the necessary mocked data.

After you implement one or more methods, make sure the driver respects the base
NAPALM API. To check this, simply execute ``tox`` on the command line.

### Other files

Some other stuff you have to do:

* `setup.py` - Set yourself as the author and set the correct `name`.
* `requirements.txt` - Make sure requirements are up to date.
