aioesphomeapi
=============

``aioesphomeapi`` allows you to interact with devices flashed with `ESPHome <https://esphome.io/>`_.

Installation
------------

The module is available from the `Python Package Index <https://pypi.python.org/pypi>`_.

.. code:: bash

    $ pip3 install aioesphomeapi

Usage
-----

It's required that you enable the `Native API <https://esphome.io/components/api.html>`_ component for the device.

.. code:: yaml

   # Example configuration entry
   api:
     password: 'MyPassword'

Check the output to get the local address of the device or use the ``name:``under ``esphome:`` from the device configuration.

.. code:: bash

   [17:56:38][C][api:095]: API Server:
   [17:56:38][C][api:096]:   Address: api_test.local:6053


The sample code below will connect to the device and retrieve details.

.. code:: python

   import aioesphomeapi
   import asyncio
   
   async def main():
       """Connect to an ESPHome device and get details."""
       loop = asyncio.get_running_loop()
   
       # Establish connection 
       api = aioesphomeapi.APIClient(loop, "api_test.local", 6053, "MyPassword")
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
       loop = asyncio.get_running_loop()
       cli = aioesphomeapi.APIClient(loop, "api_test.local", 6053, "MyPassword")
       
       await cli.connect(login=True)

       def change_callback(state):
           """Print the state changes of the device.."""
           print(state)
       
       # Subscribe to the state changes
       await cli.subscribe_states(change_callback)
   
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
    $ pip3 install -r requirements_test.txt

    # Run linters & test
    $ script/lint
    # Update protobuf _pb2.py definitions (requires a protobuf compiler installation)
    $ script/gen-protoc

License
-------

``aioesphomeapi`` is licensed under MIT, for more details check LICENSE.
