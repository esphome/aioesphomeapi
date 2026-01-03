aioesphomeapi
=============

.. image:: https://github.com/esphome/aioesphomeapi/workflows/CI/badge.svg
   :target: https://github.com/esphome/aioesphomeapi/actions/workflows/ci.yml?query=branch%3Amain

.. image:: https://img.shields.io/pypi/v/aioesphomeapi.svg
    :target: https://pypi.org/project/aioesphomeapi/

.. image:: https://codecov.io/gh/esphome/aioesphomeapi/branch/main/graph/badge.svg
   :target: https://app.codecov.io/gh/esphome/aioesphomeapi/tree/main

.. image:: https://img.shields.io/endpoint?url=https://codspeed.io/badge.json
   :target: https://codspeed.io/esphome/aioesphomeapi

``aioesphomeapi`` allows you to interact with devices flashed with `ESPHome <https://esphome.io/>`_.

Installation
------------

The module is available from the `Python Package Index <https://pypi.org/>`_.

.. code:: bash

    $ pip3 install aioesphomeapi

An optional cython extension is available for better performance, and the module will try to build it automatically.

The extension requires a C compiler and Python development headers. The module will fall back to the pure Python implementation if they are unavailable.

Building the extension can be forcefully disabled by setting the environment variable ``SKIP_CYTHON`` to ``1``.

Usage
-----

It's required that you enable the `Native API <https://esphome.io/components/api/>`_ component for the device.

.. code:: yaml

   # Example configuration entry
   api:

For secure communication, use encryption (recommended):

.. code:: yaml

   api:
     encryption:
       key: !secret api_encryption_key

Generate an encryption key with ``openssl rand -base64 32`` or visit https://esphome.io/components/api/

**Note:** Password authentication was removed in ESPHome 2026.1.0. Encryption is optional but recommended for security.

To connect to older devices still using password authentication:

.. code:: python

   api = aioesphomeapi.APIClient("device.local", 6053, password="MyPassword")

Check the output to get the local address of the device or use the ``name:`` under ``esphome:`` from the device configuration.

.. code:: bash

   [17:56:38][C][api:095]: API Server:
   [17:56:38][C][api:096]:   Address: api_test.local:6053


The sample code below will connect to the device and retrieve details.

.. code:: python

   import aioesphomeapi
   import asyncio

   async def main():
       """Connect to an ESPHome device and get details."""

       # Establish connection
       api = aioesphomeapi.APIClient(
           "api_test.local",
           6053,
           noise_psk="YOUR_ENCRYPTION_KEY",  # Remove if not using encryption
       )
       await api.connect(login=True)

       # Get API version of the device's firmware
       print(api.api_version)

       # Show device details
       device_info = await api.device_info()
       print(device_info)

       # List all entities of the device
       entities = await api.list_entities_services()
       print(entities)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())

Subscribe to state changes of an ESPHome device.

.. code:: python

   import aioesphomeapi
   import asyncio

   async def main():
       """Connect to an ESPHome device and wait for state changes."""
       api = aioesphomeapi.APIClient(
           "api_test.local",
           6053,
           noise_psk="YOUR_ENCRYPTION_KEY",  # Remove if not using encryption
       )
       await api.connect(login=True)

       def change_callback(state):
           """Print the state changes of the device."""
           print(state)

       # Subscribe to the state changes
       api.subscribe_states(change_callback)

   loop = asyncio.get_event_loop()
   try:
       asyncio.ensure_future(main())
       loop.run_forever()
   except KeyboardInterrupt:
       pass
   finally:
       loop.close()

Other examples:

- `Camera <https://gist.github.com/micw/202f9dee5c990f0b0f7e7c36b567d92b>`_
- `Async print <https://gist.github.com/fpletz/d071c72e45d17ba274fd61ca7a465033#file-esphome-print-async-py>`_
- `Simple print <https://gist.github.com/fpletz/d071c72e45d17ba274fd61ca7a465033#file-esphome-print-simple-py>`_
- `InfluxDB <https://gist.github.com/fpletz/d071c72e45d17ba274fd61ca7a465033#file-esphome-sensor-influxdb-py>`_

Development
-----------

For development is recommended to use a Python virtual environment (``venv``).

.. code:: bash

    # Setup virtualenv (optional)
    $ python3 -m venv .
    $ source bin/activate
    # Install aioesphomeapi and development depenencies
    $ pip3 install -e .
    $ pip3 install -r requirements/test.txt

    # Run linters & test
    $ script/lint
    # Update protobuf _pb2.py definitions (requires a protobuf compiler installation)
    $ script/gen-protoc

A cli tool is also available for watching logs:

.. code:: bash

   aioesphomeapi-logs --help

A cli tool is also available to discover devices:

.. code:: bash

   aioesphomeapi-discover --help


License
-------

``aioesphomeapi`` is licensed under MIT, for more details check LICENSE.
