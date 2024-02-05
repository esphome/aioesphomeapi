from __future__ import annotations

import asyncio
import logging
from functools import partial
from ipaddress import ip_address
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from zeroconf import (
    DNSAddress,
    DNSPointer,
    DNSRecord,
    RecordUpdate,
    Zeroconf,
    current_time_millis,
)
from zeroconf.asyncio import AsyncZeroconf
from zeroconf.const import _CLASS_IN, _TYPE_A, _TYPE_PTR

from aioesphomeapi import APIConnectionError, RequiresEncryptionAPIError
from aioesphomeapi._frame_helper.plain_text import APIPlaintextFrameHelper
from aioesphomeapi.client import APIClient
from aioesphomeapi.reconnect_logic import (
    MAXIMUM_BACKOFF_TRIES,
    ReconnectLogic,
    ReconnectLogicState,
)

from .common import (
    get_mock_async_zeroconf,
    get_mock_zeroconf,
    mock_data_received,
    send_plaintext_connect_response,
    send_plaintext_hello,
)
from .conftest import _create_mock_transport_protocol

logging.getLogger("aioesphomeapi").setLevel(logging.DEBUG)


async def slow_connect_fail(*args, **kwargs):
    await asyncio.sleep(10)
    raise APIConnectionError


async def quick_connect_fail(*args, **kwargs):
    raise APIConnectionError


@pytest.mark.asyncio
async def test_reconnect_logic_name_from_host():
    """Test that the name is set correctly from the host."""
    cli = APIClient(
        address="mydevice.local",
        port=6052,
        password=None,
    )

    async def on_disconnect(expected_disconnect: bool) -> None:
        pass

    async def on_connect() -> None:
        pass

    ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=MagicMock(spec=AsyncZeroconf),
    )
    assert cli.log_name == "mydevice.local"


@pytest.mark.asyncio
async def test_reconnect_logic_name_from_host_and_set():
    """Test that the name is set correctly from the host."""
    cli = APIClient(
        address="mydevice.local",
        port=6052,
        password=None,
    )

    async def on_disconnect(expected_disconnect: bool) -> None:
        pass

    async def on_connect() -> None:
        pass

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )
    assert rl.name == "mydevice"
    assert cli.log_name == "mydevice.local"


@pytest.mark.asyncio
async def test_reconnect_logic_name_from_address():
    """Test that the name is set correctly from the address."""
    cli = APIClient(
        address="1.2.3.4",
        port=6052,
        password=None,
    )

    async def on_disconnect(expected_disconnect: bool) -> None:
        pass

    async def on_connect() -> None:
        pass

    ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
    )
    assert cli.log_name == "1.2.3.4"


@pytest.mark.asyncio
async def test_reconnect_logic_name_from_name():
    """Test that the name is set correctly from the address."""
    cli = APIClient(
        address="1.2.3.4",
        port=6052,
        password=None,
    )

    async def on_disconnect(expected_disconnect: bool) -> None:
        pass

    async def on_connect() -> None:
        pass

    ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )
    assert cli.log_name == "mydevice @ 1.2.3.4"


@pytest.mark.asyncio
async def test_reconnect_logic_name_from_cli_address():
    """Test that the name is set correctly from the address."""
    cli = APIClient(
        address="mydevice",
        port=6052,
        password=None,
    )

    async def on_disconnect(expected_disconnect: bool) -> None:
        pass

    async def on_connect() -> None:
        pass

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
    )
    assert cli.log_name == "mydevice"
    assert rl.name == "mydevice"


@pytest.mark.asyncio
async def test_reconnect_logic_state(patchable_api_client: APIClient):
    """Test that reconnect logic state changes."""
    on_disconnect_called = []
    on_connect_called = []
    on_connect_fail_called = []

    cli = patchable_api_client

    async def on_disconnect(expected_disconnect: bool) -> None:
        nonlocal on_disconnect_called
        on_disconnect_called.append(expected_disconnect)

    async def on_connect() -> None:
        nonlocal on_connect_called
        on_connect_called.append(True)

    async def on_connect_fail(connect_exception: Exception) -> None:
        nonlocal on_connect_called
        on_connect_fail_called.append(connect_exception)

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
        on_connect_error=on_connect_fail,
    )
    assert cli.log_name == "mydevice @ 1.2.3.4"

    with patch.object(cli, "start_connection", side_effect=APIConnectionError):
        await rl.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert len(on_disconnect_called) == 0
    assert len(on_connect_called) == 0
    assert len(on_connect_fail_called) == 1
    assert isinstance(on_connect_fail_called[-1], APIConnectionError)
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED
    assert rl._tries == 1

    with (
        patch.object(cli, "start_connection"),
        patch.object(cli, "finish_connection", side_effect=RequiresEncryptionAPIError),
    ):
        await rl.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert len(on_disconnect_called) == 0
    assert len(on_connect_called) == 0
    assert len(on_connect_fail_called) == 2
    assert isinstance(on_connect_fail_called[-1], RequiresEncryptionAPIError)
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED
    assert rl._tries == MAXIMUM_BACKOFF_TRIES

    with patch.object(cli, "start_connection"), patch.object(cli, "finish_connection"):
        await rl.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert len(on_disconnect_called) == 0
    assert len(on_connect_called) == 1
    assert len(on_connect_fail_called) == 2
    assert rl._connection_state is ReconnectLogicState.READY
    assert rl._tries == 0
    await rl.stop()
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


@pytest.mark.asyncio
async def test_reconnect_retry(
    patchable_api_client: APIClient, caplog: pytest.LogCaptureFixture
):
    """Test that reconnect logic retry."""
    on_disconnect_called = []
    on_connect_called = []
    on_connect_fail_called = []
    cli = patchable_api_client

    async def on_disconnect(expected_disconnect: bool) -> None:
        nonlocal on_disconnect_called
        on_disconnect_called.append(expected_disconnect)

    async def on_connect() -> None:
        nonlocal on_connect_called
        on_connect_called.append(True)

    async def on_connect_fail(connect_exception: Exception) -> None:
        nonlocal on_connect_called
        on_connect_fail_called.append(connect_exception)

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
        on_connect_error=on_connect_fail,
    )
    assert cli.log_name == "mydevice @ 1.2.3.4"
    caplog.clear()

    with patch.object(cli, "start_connection", side_effect=APIConnectionError):
        await rl.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert len(on_disconnect_called) == 0
    assert len(on_connect_called) == 0
    assert len(on_connect_fail_called) == 1
    assert isinstance(on_connect_fail_called[-1], APIConnectionError)
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED
    assert "connect to ESPHome API for mydevice @ 1.2.3.4" in caplog.text
    for record in caplog.records:
        if "connect to ESPHome API for mydevice @ 1.2.3.4" in record.message:
            assert record.levelno == logging.WARNING

    caplog.clear()
    # Next retry should run at debug level
    with patch.object(cli, "start_connection", side_effect=APIConnectionError):
        # Should now retry
        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert len(on_disconnect_called) == 0
    assert len(on_connect_called) == 0
    assert len(on_connect_fail_called) == 2
    assert isinstance(on_connect_fail_called[-1], APIConnectionError)
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED
    assert "connect to ESPHome API for mydevice @ 1.2.3.4" in caplog.text
    for record in caplog.records:
        if "connect to ESPHome API for mydevice @ 1.2.3.4" in record.message:
            assert record.levelno == logging.DEBUG

    caplog.clear()
    with patch.object(cli, "start_connection"), patch.object(cli, "finish_connection"):
        # Should now retry
        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert "connect to ESPHome API for mydevice @ 1.2.3.4" not in caplog.text
    assert len(on_disconnect_called) == 0
    assert len(on_connect_called) == 1
    assert len(on_connect_fail_called) == 2
    assert rl._connection_state is ReconnectLogicState.READY
    original_when = rl._connect_timer.when()

    # Ensure starting the connection logic again does not trigger a new connection
    await rl.start()
    # Verify no new timer is started
    assert rl._connect_timer.when() == original_when

    await rl.stop()
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


DNS_POINTER = DNSPointer(
    "_esphomelib._tcp.local.",
    _TYPE_PTR,
    _CLASS_IN,
    1000,
    "mydevice._esphomelib._tcp.local.",
)


@pytest.mark.parametrize(
    ("record", "should_trigger_zeroconf", "expected_state_after_trigger", "log_text"),
    (
        (
            DNS_POINTER,
            True,
            ReconnectLogicState.READY,
            "received mDNS record",
        ),
        (
            DNSPointer(
                "_esphomelib._tcp.local.",
                _TYPE_PTR,
                _CLASS_IN,
                1000,
                "wrong_name._esphomelib._tcp.local.",
            ),
            False,
            ReconnectLogicState.CONNECTING,
            "",
        ),
        (
            DNSAddress(
                "mydevice.local.",
                _TYPE_A,
                _CLASS_IN,
                1000,
                ip_address("1.2.3.4").packed,
            ),
            True,
            ReconnectLogicState.READY,
            "received mDNS record",
        ),
    ),
)
@pytest.mark.asyncio
async def test_reconnect_zeroconf(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
    record: DNSRecord,
    should_trigger_zeroconf: bool,
    expected_state_after_trigger: ReconnectLogicState,
    log_text: str,
) -> None:
    """Test that reconnect logic retry."""

    cli = patchable_api_client

    mock_zeroconf = MagicMock(spec=Zeroconf)

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=mock_zeroconf,
        name="mydevice",
        on_connect_error=AsyncMock(),
    )
    assert cli.log_name == "mydevice @ 1.2.3.4"

    with patch.object(
        cli, "start_connection", side_effect=quick_connect_fail
    ) as mock_start_connection:
        await rl.start()
        await asyncio.sleep(0)

    assert mock_start_connection.call_count == 1

    with patch.object(
        cli, "start_connection", side_effect=slow_connect_fail
    ) as mock_start_connection:
        assert rl._connection_state is ReconnectLogicState.DISCONNECTED
        assert rl._accept_zeroconf_records is True
        assert not rl._is_stopped

        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)
        assert mock_start_connection.call_count == 1
        assert rl._connection_state is ReconnectLogicState.CONNECTING
        assert rl._accept_zeroconf_records is True
        assert not rl._is_stopped

    caplog.clear()
    with (
        patch.object(cli, "start_connection") as mock_start_connection,
        patch.object(cli, "finish_connection"),
    ):
        assert rl._zc_listening is True
        rl.async_update_records(
            mock_zeroconf, current_time_millis(), [RecordUpdate(record, None)]
        )
        assert (
            "Triggering connect because of received mDNS record" in caplog.text
        ) is should_trigger_zeroconf
        assert rl._accept_zeroconf_records is not should_trigger_zeroconf
        assert rl._zc_listening is True  # should change after one iteration of the loop
        await asyncio.sleep(0)
        assert rl._zc_listening is not should_trigger_zeroconf

        # The reconnect is scheduled to run in the next loop iteration
        await asyncio.sleep(0)
        assert mock_start_connection.call_count == int(should_trigger_zeroconf)
        assert log_text in caplog.text

    assert rl._connection_state is expected_state_after_trigger
    await rl.stop()
    assert rl._is_stopped is True
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


@pytest.mark.asyncio
async def test_reconnect_zeroconf_not_while_handshaking(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that reconnect logic retry will not trigger a zeroconf reconnect while handshaking."""
    cli = patchable_api_client

    mock_zeroconf = MagicMock(spec=Zeroconf)

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=mock_zeroconf,
        name="mydevice",
        on_connect_error=AsyncMock(),
    )
    assert cli.log_name == "mydevice @ 1.2.3.4"

    with patch.object(
        cli, "start_connection", side_effect=quick_connect_fail
    ) as mock_start_connection:
        await rl.start()
        await asyncio.sleep(0)

    assert mock_start_connection.call_count == 1

    with (
        patch.object(cli, "start_connection") as mock_start_connection,
        patch.object(
            cli, "finish_connection", side_effect=slow_connect_fail
        ) as mock_finish_connection,
    ):
        assert rl._connection_state is ReconnectLogicState.DISCONNECTED
        assert rl._accept_zeroconf_records is True
        assert not rl._is_stopped

        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)
        assert mock_start_connection.call_count == 1
        assert mock_finish_connection.call_count == 1
        assert rl._connection_state is ReconnectLogicState.HANDSHAKING
        assert rl._accept_zeroconf_records is False
        assert not rl._is_stopped

    rl.async_update_records(
        mock_zeroconf, current_time_millis(), [RecordUpdate(DNS_POINTER, None)]
    )
    assert (
        "Triggering connect because of received mDNS record" in caplog.text
    ) is False

    rl._cancel_connect("forced cancel in test")
    await rl.stop()
    assert rl._is_stopped is True
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


@pytest.mark.asyncio
async def test_connect_task_not_cancelled_while_handshaking(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that reconnect logic will not cancel an in progress handshake."""
    cli = patchable_api_client

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        name="mydevice",
        on_connect_error=AsyncMock(),
    )
    assert cli.log_name == "mydevice @ 1.2.3.4"

    with patch.object(
        cli, "start_connection", side_effect=quick_connect_fail
    ) as mock_start_connection:
        await rl.start()
        await asyncio.sleep(0)

    assert mock_start_connection.call_count == 1

    with (
        patch.object(cli, "start_connection") as mock_start_connection,
        patch.object(
            cli, "finish_connection", side_effect=slow_connect_fail
        ) as mock_finish_connection,
    ):
        assert rl._connection_state is ReconnectLogicState.DISCONNECTED
        assert rl._accept_zeroconf_records is True
        assert not rl._is_stopped

        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)
        assert mock_start_connection.call_count == 1
        assert mock_finish_connection.call_count == 1
        assert rl._connection_state is ReconnectLogicState.HANDSHAKING
        assert rl._accept_zeroconf_records is False
        assert not rl._is_stopped

    caplog.clear()
    # This can likely never happen in practice, but we should handle it
    # in the event there is a race as the consequence is that we could
    # disconnect a working connection.
    rl._call_connect_once()
    assert (
        "Not cancelling existing connect task as its already ReconnectLogicState.HANDSHAKING"
        in caplog.text
    )

    rl._cancel_connect("forced cancel in test")
    await rl.stop()
    assert rl._is_stopped is True
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


@pytest.mark.asyncio
async def test_connect_aborts_if_stopped(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that reconnect logic will abort connecting if stopped."""
    cli = patchable_api_client

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        name="mydevice",
        on_connect_error=AsyncMock(),
    )
    assert cli.log_name == "mydevice @ 1.2.3.4"

    with patch.object(
        cli, "start_connection", side_effect=quick_connect_fail
    ) as mock_start_connection:
        await rl.start()
        await asyncio.sleep(0)

    assert mock_start_connection.call_count == 1

    with patch.object(cli, "start_connection") as mock_start_connection:
        timer = rl._connect_timer
        assert timer is not None
        await rl.stop()
        assert rl._is_stopped is True
        rl._call_connect_once()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    # We should never try to connect again
    # once we are stopped
    assert mock_start_connection.call_count == 0
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


@pytest.mark.asyncio
async def test_reconnect_logic_stop_callback(patchable_api_client: APIClient):
    """Test that the stop_callback stops the ReconnectLogic."""
    cli = patchable_api_client
    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )
    await rl.start()
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED
    await asyncio.sleep(0)
    assert rl._connection_state is ReconnectLogicState.CONNECTING
    assert rl._is_stopped is False
    rl.stop_callback()
    # Wait for cancellation to propagate
    for _ in range(4):
        await asyncio.sleep(0)
    assert rl._is_stopped is True
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


@pytest.mark.asyncio
async def test_reconnect_logic_stop_callback_waits_for_handshake(
    patchable_api_client: APIClient,
):
    """Test that the stop_callback waits for a handshake."""
    cli = patchable_api_client
    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED

    with (
        patch.object(cli, "start_connection"),
        patch.object(cli, "finish_connection", side_effect=slow_connect_fail),
    ):
        await rl.start()
        for _ in range(3):
            await asyncio.sleep(0)

    assert rl._connection_state is ReconnectLogicState.HANDSHAKING
    assert rl._is_stopped is False
    rl.stop_callback()
    # Wait for cancellation to propagate
    for _ in range(4):
        await asyncio.sleep(0)
    assert rl._is_stopped is False
    assert rl._connection_state is ReconnectLogicState.HANDSHAKING

    rl._cancel_connect("forced cancel in test")
    # Wait for cancellation to propagate
    for _ in range(4):
        await asyncio.sleep(0)
    assert rl._is_stopped is True
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


@pytest.mark.asyncio
async def test_handling_unexpected_disconnect(aiohappyeyeballs_start_connection):
    """Test the disconnect callback fires with expected_disconnect=False."""
    loop = asyncio.get_event_loop()
    protocol: APIPlaintextFrameHelper | None = None
    transport = MagicMock()
    connected = asyncio.Event()

    class PatchableAPIClient(APIClient):
        pass

    async_zeroconf = get_mock_async_zeroconf()

    cli = PatchableAPIClient(
        address="1.2.3.4",
        port=6052,
        password=None,
        noise_psk=None,
        expected_name="fake",
        zeroconf_instance=async_zeroconf.zeroconf,
    )

    connected = asyncio.Event()
    on_disconnect_calls = []

    async def on_disconnect(expected_disconnect: bool) -> None:
        on_disconnect_calls.append(expected_disconnect)

    async def on_connect() -> None:
        connected.set()

    logic = ReconnectLogic(
        client=cli,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        zeroconf_instance=async_zeroconf,
        name="fake",
    )

    with patch.object(
        loop,
        "create_connection",
        side_effect=partial(_create_mock_transport_protocol, transport, connected),
    ):
        await logic.start()
        await connected.wait()
        protocol = cli._connection._frame_helper
        send_plaintext_hello(protocol)
        send_plaintext_connect_response(protocol, False)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert cli._connection.is_connected is True
    await asyncio.sleep(0)

    with patch.object(
        loop,
        "create_connection",
        side_effect=partial(_create_mock_transport_protocol, transport, connected),
    ) as mock_create_connection:
        protocol.eof_received()
        # Wait for the task to run
        await asyncio.sleep(0)
        # Ensure we try to reconnect immediately
        # since its an unexpected disconnect
        assert mock_create_connection.call_count == 0

    assert len(on_disconnect_calls) == 1
    expected_disconnect = on_disconnect_calls[-1]
    assert expected_disconnect is False
    await logic.stop()


@pytest.mark.asyncio
async def test_backoff_on_encryption_error(
    caplog: pytest.LogCaptureFixture,
    aiohappyeyeballs_start_connection,
) -> None:
    """Test we backoff on encryption error."""
    loop = asyncio.get_event_loop()
    protocol: APIPlaintextFrameHelper | None = None
    transport = MagicMock()
    connected = asyncio.Event()

    class PatchableAPIClient(APIClient):
        pass

    async_zeroconf = get_mock_async_zeroconf()

    cli = PatchableAPIClient(
        address="1.2.3.4",
        port=6052,
        password=None,
        noise_psk="",
        expected_name="fake",
        zeroconf_instance=async_zeroconf.zeroconf,
    )

    connected = asyncio.Event()
    on_disconnect_calls = []

    async def on_disconnect(expected_disconnect: bool) -> None:
        on_disconnect_calls.append(expected_disconnect)

    async def on_connect() -> None:
        connected.set()

    logic = ReconnectLogic(
        client=cli,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        zeroconf_instance=async_zeroconf,
        name="fake",
    )

    with patch.object(
        loop,
        "create_connection",
        side_effect=partial(_create_mock_transport_protocol, transport, connected),
    ):
        await logic.start()
        await connected.wait()
        protocol = cli._connection._frame_helper
        mock_data_received(protocol, b"\x01\x00\x00")

    assert cli._connection.is_connected is False
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert len(on_disconnect_calls) == 0

    assert "Scheduling new connect attempt in 60.00 seconds" in caplog.text
    assert "Connection requires encryption (RequiresEncryptionAPIError)" in caplog.text
    now = loop.time()
    assert logic._connect_timer.when() - now == pytest.approx(60, 1)
    assert logic._tries == MAXIMUM_BACKOFF_TRIES
    await logic.stop()
